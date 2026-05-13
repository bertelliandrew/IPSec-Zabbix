<?php

require_once("/etc/inc/globals.inc");
require_once("/etc/inc/functions.inc");
require_once("/etc/inc/config.inc");
require_once("interfaces.inc");
require_once("ipsec.inc");

$result = new stdClass();
$result->data = array();

function getConfigPathCompat($path, $default = array()) {
    global $config;

    if (function_exists('config_get_path')) {
        return config_get_path($path, $default);
    }

    $parts = explode('/', $path);
    $current = $config;

    foreach ($parts as $part) {
        if (!isset($current[$part])) {
            return $default;
        }

        $current = $current[$part];
    }

    return $current;
}

function ensureList($value) {
    if (!is_array($value)) {
        return array();
    }

    if (isset($value['item']) && is_array($value['item'])) {
        return ensureList($value['item']);
    }

    if (
        isset($value['ikeid']) ||
        isset($value['descr']) ||
        isset($value['remote-gateway']) ||
        isset($value['localid']) ||
        isset($value['remoteid'])
    ) {
        return array($value);
    }

    return $value;
}

function normalizeCidr($ip, $bits) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return "";
    }

    $bits = (int)$bits;

    if ($bits < 0 || $bits > 32) {
        return "";
    }

    if ($bits == 0) {
        return "0.0.0.0/0";
    }

    $ipLong = ip2long($ip);
    $mask = (0xffffffff << (32 - $bits)) & 0xffffffff;
    $network = $ipLong & $mask;

    return long2ip($network) . "/" . $bits;
}

function parseCidr($cidr) {
    $parts = explode("/", $cidr);

    if (count($parts) != 2) {
        return false;
    }

    $ip = $parts[0];
    $bits = (int)$parts[1];

    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }

    if ($bits < 0 || $bits > 32) {
        return false;
    }

    return array(
        "ip" => $ip,
        "bits" => $bits
    );
}

function ipInCidr($ip, $cidr) {
    $parsed = parseCidr($cidr);

    if ($parsed === false) {
        return false;
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }

    $bits = $parsed["bits"];

    if ($bits == 0) {
        return true;
    }

    $ipLong = ip2long($ip);
    $networkLong = ip2long($parsed["ip"]);
    $mask = (0xffffffff << (32 - $bits)) & 0xffffffff;

    return (($ipLong & $mask) == ($networkLong & $mask));
}

function getInterfaceCidr($ifName) {
    $ifName = strtolower((string)$ifName);

    if ($ifName == "") {
        return "";
    }

    $ip = "";
    $bits = "";

    if (function_exists("get_interface_ip")) {
        $ip = get_interface_ip($ifName);
    }

    if (function_exists("get_interface_subnet")) {
        $bits = get_interface_subnet($ifName);
    }

    if ($ip != "" && $bits != "") {
        return normalizeCidr($ip, $bits);
    }

    return "";
}

function getCidrFromIpsecId($id) {
    if (!is_array($id)) {
        return "";
    }

    $type = isset($id["type"]) ? strtolower((string)$id["type"]) : "";

    if ($type == "network" || $type == "address" || $type == "host") {
        $address = isset($id["address"]) ? (string)$id["address"] : "";

        if ($address == "") {
            return "";
        }

        if (isset($id["netbits"])) {
            $bits = (int)$id["netbits"];
        } elseif (isset($id["bits"])) {
            $bits = (int)$id["bits"];
        } elseif ($type == "address" || $type == "host") {
            $bits = 32;
        } else {
            $bits = 32;
        }

        return normalizeCidr($address, $bits);
    }

    $interfaceCidr = getInterfaceCidr($type);

    if ($interfaceCidr != "") {
        return $interfaceCidr;
    }

    if ($type == "any") {
        return "0.0.0.0/0";
    }

    return "";
}

function findLocalSourceIpForCidr($localCidr) {
    $interfaces = getConfigPathCompat("interfaces", array());

    if (!is_array($interfaces)) {
        return "";
    }

    foreach ($interfaces as $ifName => $ifCfg) {
        $ip = "";

        if (function_exists("get_interface_ip")) {
            $ip = get_interface_ip($ifName);
        }

        if ($ip == "") {
            continue;
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            continue;
        }

        if (ipInCidr($ip, $localCidr)) {
            return $ip;
        }
    }

    return "";
}

function getPhase1Map() {
    $phase1Raw = getConfigPathCompat("ipsec/phase1", array());
    $phase1List = ensureList($phase1Raw);
    $map = array();

    foreach ($phase1List as $idx => $p1) {
        if (!is_array($p1)) {
            continue;
        }

        if (isset($p1["disabled"])) {
            continue;
        }

        if (isset($p1["ikeid"])) {
            $ikeid = (string)$p1["ikeid"];
        } else {
            $ikeid = (string)($idx + 1);
        }

        $map[$ikeid] = $p1;
    }

    return $map;
}

function getIpsecPhase2Entries() {
    $entries = array();

    if (!function_exists("ipsec_enabled") || !ipsec_enabled()) {
        return $entries;
    }

    $phase1Map = getPhase1Map();
    $phase2Raw = getConfigPathCompat("ipsec/phase2", array());
    $phase2List = ensureList($phase2Raw);

    foreach ($phase2List as $p2Index => $p2) {
        if (!is_array($p2)) {
            continue;
        }

        if (isset($p2["disabled"])) {
            continue;
        }

        $ikeid = isset($p2["ikeid"]) ? (string)$p2["ikeid"] : "";

        if ($ikeid == "" || !isset($phase1Map[$ikeid])) {
            continue;
        }

        $p1 = $phase1Map[$ikeid];

        $p1Name = isset($p1["descr"]) && trim($p1["descr"]) !== ""
            ? trim($p1["descr"])
            : "IKEID_" . $ikeid;

        $p2Name = isset($p2["descr"]) && trim($p2["descr"]) !== ""
            ? trim($p2["descr"])
            : $p1Name . "_P2_" . $p2Index;

        $remoteGateway = isset($p1["remote-gateway"])
            ? (string)$p1["remote-gateway"]
            : "";

        $conid = function_exists("ipsec_conid")
            ? ipsec_conid($p1)
            : "con" . $ikeid;

        $localCidr = isset($p2["localid"])
            ? getCidrFromIpsecId($p2["localid"])
            : "";

        $remoteCidr = isset($p2["remoteid"])
            ? getCidrFromIpsecId($p2["remoteid"])
            : "";

        $pingHost = isset($p2["pinghost"])
            ? trim((string)$p2["pinghost"])
            : "";

        if (isset($p2["uniqid"])) {
            $p2id = (string)$p2["uniqid"];
        } elseif (isset($p2["reqid"])) {
            $p2id = (string)$p2["reqid"];
        } else {
            $p2id = (string)$p2Index;
        }

        $entries[] = array(
            "ikeid" => $ikeid,
            "conid" => (string)$conid,
            "p1_name" => (string)$p1Name,
            "p2_name" => (string)$p2Name,
            "p2id" => (string)$p2id,
            "remote_gateway" => (string)$remoteGateway,
            "local_network" => (string)$localCidr,
            "remote_network" => (string)$remoteCidr,
            "pinghost" => (string)$pingHost
        );
    }

    return $entries;
}

function getActiveIpsecSas() {
    if (!function_exists("ipsec_list_sa")) {
        return array();
    }

    $sas = ipsec_list_sa();

    if (!is_array($sas)) {
        return array();
    }

    return $sas;
}

function getIpsecSaStatus($conid, $sas) {
    foreach ($sas as $ikesa) {
        if (!isset($ikesa["con-id"])) {
            continue;
        }

        if ($ikesa["con-id"] != $conid) {
            continue;
        }

        $state = isset($ikesa["state"])
            ? strtoupper((string)$ikesa["state"])
            : "";

        $childCount = 0;

        if (isset($ikesa["child-sas"]) && is_array($ikesa["child-sas"])) {
            $childCount = count($ikesa["child-sas"]);
        }

        if ($state == "ESTABLISHED" && $childCount > 0) {
            return array(
                "status" => 1,
                "status_text" => "UP",
                "ike_state" => $state,
                "child_sa_count" => $childCount
            );
        }

        return array(
            "status" => 0,
            "status_text" => "DOWN",
            "ike_state" => $state,
            "child_sa_count" => $childCount
        );
    }

    return array(
        "status" => 0,
        "status_text" => "DOWN",
        "ike_state" => "NOT_FOUND",
        "child_sa_count" => 0
    );
}

function probeLanToLan($source, $target, $remoteNetwork) {
    if ($target == "") {
        return array(
            "status" => 2,
            "status_text" => "NO_PINGHOST_CONFIGURED"
        );
    }

    if ($source == "") {
        return array(
            "status" => 2,
            "status_text" => "NO_LOCAL_SOURCE_IP"
        );
    }

    if (!filter_var($source, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return array(
            "status" => 2,
            "status_text" => "INVALID_SOURCE_IP"
        );
    }

    if (!filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return array(
            "status" => 2,
            "status_text" => "INVALID_PINGHOST"
        );
    }

    if ($remoteNetwork != "" && !ipInCidr($target, $remoteNetwork)) {
        return array(
            "status" => 2,
            "status_text" => "PINGHOST_OUTSIDE_REMOTE_NETWORK"
        );
    }

    $cmd = "/sbin/ping -S " . escapeshellarg($source) .
           " -c 2 -o " . escapeshellarg($target) .
           " >/dev/null 2>&1";

    exec($cmd, $output, $returnCode);

    if ($returnCode === 0) {
        return array(
            "status" => 1,
            "status_text" => "UP"
        );
    }

    return array(
        "status" => 0,
        "status_text" => "DOWN"
    );
}

$entries = getIpsecPhase2Entries();
$sas = getActiveIpsecSas();

foreach ($entries as $entry) {
    $sourceIp = findLocalSourceIpForCidr($entry["local_network"]);
    $targetIp = $entry["pinghost"];

    $saStatus = getIpsecSaStatus($entry["conid"], $sas);
    $probeStatus = probeLanToLan($sourceIp, $targetIp, $entry["remote_network"]);

    if ($saStatus["status"] == 1 && $probeStatus["status"] == 1) {
        $finalStatus = 1;
        $finalStatusText = "UP";
    } elseif ($probeStatus["status"] == 2) {
        $finalStatus = 2;
        $finalStatusText = $probeStatus["status_text"];
    } else {
        $finalStatus = 0;
        $finalStatusText = "DOWN";
    }

    $result->data[] = array(
        "p1_name" => $entry["p1_name"],
        "p2_name" => $entry["p2_name"],
        "ikeid" => $entry["ikeid"],
        "p2id" => $entry["p2id"],
        "conid" => $entry["conid"],
        "remote_gateway" => $entry["remote_gateway"],

        "local_network" => $entry["local_network"],
        "remote_network" => $entry["remote_network"],

        "probe_source" => $sourceIp,
        "probe_target" => $targetIp,

        "ipsec_status" => $saStatus["status"],
        "ipsec_status_text" => $saStatus["status_text"],
        "ike_state" => $saStatus["ike_state"],
        "child_sa_count" => $saStatus["child_sa_count"],

        "probe_status" => $probeStatus["status"],
        "probe_status_text" => $probeStatus["status_text"],

        "final_status" => $finalStatus,
        "final_status_text" => $finalStatusText
    );
}

echo json_encode($result, JSON_PRETTY_PRINT);

exit;