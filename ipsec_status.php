<?php

/*
 * pfSense IPsec Monitor for Zabbix
 *
 * This script monitors pfSense IPsec tunnels by separating:
 *
 * - Phase 1 status:
 *   Checks if the IKE SA is established.
 *
 * - Phase 2 status:
 *   Checks if LAN-to-LAN communication is really working by pinging
 *   the "Automatically ping host" configured in each Phase 2.
 *
 * The goal is to avoid false positives where IPsec appears online,
 * but traffic between LANs is not working.
 *
 * JSON output:
 *
 * {
 *   "phase1": [],
 *   "phase2": []
 * }
 *
 * Status codes:
 *
 * 1 = UP
 * 0 = DOWN
 * 2 = configuration problem / not monitorable
 */

require_once("/etc/inc/globals.inc");
require_once("/etc/inc/functions.inc");
require_once("/etc/inc/config.inc");
require_once("interfaces.inc");
require_once("ipsec.inc");

/*
 * Performance settings.
 *
 * Pings are executed in parallel.
 * The timeout prevents the script from getting stuck on unreachable peers.
 */
$PING_TIMEOUT_SECONDS = 2.0;
$PING_CONCURRENCY_LIMIT = 20;

/*
 * Optional cache.
 *
 * Keep disabled by default for Zabbix accuracy.
 * Set CACHE_TTL_SECONDS to 10 or 15 if the item is queried too frequently.
 */
$CACHE_TTL_SECONDS = 0;
$CACHE_FILE = "/tmp/pfsense_ipsec_status_cache.json";

if (
    $CACHE_TTL_SECONDS > 0 &&
    file_exists($CACHE_FILE) &&
    (time() - filemtime($CACHE_FILE)) <= $CACHE_TTL_SECONDS
) {
    echo file_get_contents($CACHE_FILE);
    exit;
}

$result = new stdClass();
$result->phase1 = array();
$result->phase2 = array();

/*
 * Reads pfSense configuration paths with compatibility between versions.
 */
function getConfigPathCompat($path, $default = array()) {
    global $config;

    if (function_exists("config_get_path")) {
        return config_get_path($path, $default);
    }

    $parts = explode("/", $path);
    $current = $config;

    foreach ($parts as $part) {
        if (!isset($current[$part])) {
            return $default;
        }

        $current = $current[$part];
    }

    return $current;
}

/*
 * Ensures pfSense config entries are always treated as a list.
 */
function ensureList($value) {
    if (!is_array($value)) {
        return array();
    }

    if (isset($value["item"]) && is_array($value["item"])) {
        return ensureList($value["item"]);
    }

    if (
        isset($value["ikeid"]) ||
        isset($value["descr"]) ||
        isset($value["remote-gateway"]) ||
        isset($value["localid"]) ||
        isset($value["remoteid"])
    ) {
        return array($value);
    }

    return $value;
}

/*
 * Converts IPv4 to unsigned integer.
 */
function ipToLongUnsigned($ip) {
    $long = ip2long($ip);

    if ($long === false) {
        return false;
    }

    return (int)sprintf("%u", $long);
}

/*
 * Converts IP + mask bits to CIDR network.
 *
 * Example:
 * 10.255.255.1/24 -> 10.255.255.0/24
 */
function normalizeCidr($ip, $bits) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return "";
    }

    $bits = (int)$bits;

    if ($bits < 0 || $bits > 32) {
        return "";
    }

    if ($bits === 0) {
        return "0.0.0.0/0";
    }

    $ipLong = ipToLongUnsigned($ip);

    if ($ipLong === false) {
        return "";
    }

    $mask = (0xffffffff << (32 - $bits)) & 0xffffffff;
    $network = $ipLong & $mask;

    return long2ip($network) . "/" . $bits;
}

/*
 * Parses a CIDR network.
 */
function parseCidr($cidr) {
    $parts = explode("/", $cidr);

    if (count($parts) !== 2) {
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

/*
 * Checks if an IP belongs to a CIDR network.
 */
function ipInCidr($ip, $cidr) {
    $parsed = parseCidr($cidr);

    if ($parsed === false) {
        return false;
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }

    $bits = $parsed["bits"];

    if ($bits === 0) {
        return true;
    }

    $ipLong = ipToLongUnsigned($ip);
    $networkLong = ipToLongUnsigned($parsed["ip"]);

    if ($ipLong === false || $networkLong === false) {
        return false;
    }

    $mask = (0xffffffff << (32 - $bits)) & 0xffffffff;

    return (($ipLong & $mask) === ($networkLong & $mask));
}

/*
 * Gets CIDR network from a pfSense interface.
 */
function getInterfaceCidr($ifName) {
    $ifName = strtolower((string)$ifName);

    if ($ifName === "") {
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

    if ($ip !== "" && $bits !== "") {
        return normalizeCidr($ip, $bits);
    }

    return "";
}

/*
 * Loads all local IPv4 interface addresses once.
 */
function getLocalInterfaceIps() {
    $interfaces = getConfigPathCompat("interfaces", array());
    $localIps = array();

    if (!is_array($interfaces)) {
        return $localIps;
    }

    foreach ($interfaces as $ifName => $ifCfg) {
        $ip = "";
        $bits = "";

        if (function_exists("get_interface_ip")) {
            $ip = get_interface_ip($ifName);
        }

        if (function_exists("get_interface_subnet")) {
            $bits = get_interface_subnet($ifName);
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            continue;
        }

        $localIps[] = array(
            "interface" => (string)$ifName,
            "ip" => (string)$ip,
            "cidr" => (string)normalizeCidr($ip, $bits)
        );
    }

    return $localIps;
}

/*
 * Converts Phase 2 localid/remoteid to CIDR.
 */
function getCidrFromIpsecId($id) {
    if (!is_array($id)) {
        return "";
    }

    $type = isset($id["type"]) ? strtolower((string)$id["type"]) : "";

    if ($type === "network" || $type === "address" || $type === "host") {
        $address = isset($id["address"]) ? (string)$id["address"] : "";

        if ($address === "") {
            return "";
        }

        if (isset($id["netbits"])) {
            $bits = (int)$id["netbits"];
        } elseif (isset($id["bits"])) {
            $bits = (int)$id["bits"];
        } elseif ($type === "address" || $type === "host") {
            $bits = 32;
        } else {
            $bits = 32;
        }

        return normalizeCidr($address, $bits);
    }

    $interfaceCidr = getInterfaceCidr($type);

    if ($interfaceCidr !== "") {
        return $interfaceCidr;
    }

    if ($type === "any") {
        return "0.0.0.0/0";
    }

    return "";
}

/*
 * Finds the local pfSense IP that belongs to the Phase 2 local network.
 * This IP is used as the ping source.
 */
function findLocalSourceIpForCidr($localCidr, $localIps) {
    if ($localCidr === "" || $localCidr === "0.0.0.0/0") {
        return "";
    }

    foreach ($localIps as $iface) {
        if (isset($iface["ip"]) && ipInCidr($iface["ip"], $localCidr)) {
            return $iface["ip"];
        }
    }

    return "";
}

/*
 * Loads enabled Phase 1 entries and indexes them by ikeid.
 */
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

/*
 * Discovers all enabled Phase 2 entries.
 */
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

        if ($ikeid === "" || !isset($phase1Map[$ikeid])) {
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

        /*
         * pinghost comes from:
         * Phase 2 > Keep Alive > Automatically ping host
         */
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

/*
 * Reads active IPsec SAs from pfSense/strongSwan.
 */
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

/*
 * Indexes SAs by con-id.
 */
function buildSaMapByConid($sas) {
    $map = array();

    foreach ($sas as $sa) {
        if (isset($sa["con-id"])) {
            $map[(string)$sa["con-id"]] = $sa;
        }
    }

    return $map;
}

/*
 * Checks Phase 1/IKE status.
 */
function getPhase1Status($conid, $saMap) {
    $conid = (string)$conid;

    if (!isset($saMap[$conid])) {
        return array(
            "status" => 0,
            "status_text" => "DOWN"
        );
    }

    $ikesa = $saMap[$conid];

    $state = isset($ikesa["state"])
        ? strtoupper((string)$ikesa["state"])
        : "";

    if ($state === "ESTABLISHED") {
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

/*
 * Validates probe configuration before running ping.
 */
function validateProbeConfig($source, $target, $remoteNetwork) {
    if ($target === "") {
        return array(
            "status" => 2,
            "status_text" => "NO_PINGHOST_CONFIGURED"
        );
    }

    if ($source === "") {
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

    if ($remoteNetwork !== "" && !ipInCidr($target, $remoteNetwork)) {
        return array(
            "status" => 2,
            "status_text" => "PINGHOST_OUTSIDE_REMOTE_NETWORK"
        );
    }

    return array(
        "status" => 9,
        "status_text" => "READY"
    );
}

/*
 * Starts one non-blocking ping process.
 */
function startPingProcess($source, $target) {
    $cmd = "exec /sbin/ping -S " . escapeshellarg($source) .
           " -c 1 -o -q " . escapeshellarg($target);

    $descriptors = array(
        0 => array("pipe", "r"),
        1 => array("pipe", "w"),
        2 => array("pipe", "w")
    );

    $pipes = array();
    $process = proc_open($cmd, $descriptors, $pipes);

    if (!is_resource($process)) {
        return false;
    }

    if (isset($pipes[0]) && is_resource($pipes[0])) {
        fclose($pipes[0]);
    }

    if (isset($pipes[1]) && is_resource($pipes[1])) {
        stream_set_blocking($pipes[1], false);
    }

    if (isset($pipes[2]) && is_resource($pipes[2])) {
        stream_set_blocking($pipes[2], false);
    }

    return array(
        "process" => $process,
        "pipes" => $pipes,
        "started_at" => microtime(true)
    );
}

/*
 * Closes or terminates a ping process.
 */
function closePingProcess($procData, $terminate = false) {
    $process = $procData["process"];
    $pipes = $procData["pipes"];

    if ($terminate) {
        proc_terminate($process);
        usleep(100000);

        $status = proc_get_status($process);

        if (isset($status["running"]) && $status["running"]) {
            proc_terminate($process, 9);
        }
    }

    if (isset($pipes[1]) && is_resource($pipes[1])) {
        fclose($pipes[1]);
    }

    if (isset($pipes[2]) && is_resource($pipes[2])) {
        fclose($pipes[2]);
    }

    return proc_close($process);
}

/*
 * Runs ping probes in parallel.
 */
function runPingJobs($jobs, $timeoutSeconds, $limit) {
    $results = array();
    $pending = $jobs;
    $active = array();

    while (!empty($pending) || !empty($active)) {
        while (count($active) < $limit && !empty($pending)) {
            $keys = array_keys($pending);
            $key = $keys[0];
            $job = $pending[$key];
            unset($pending[$key]);

            $procData = startPingProcess($job["source"], $job["target"]);

            if ($procData === false) {
                $results[$key] = array(
                    "status" => 2,
                    "status_text" => "PROBE_START_FAILED"
                );
                continue;
            }

            $active[$key] = $procData;
        }

        foreach ($active as $key => $procData) {
            $status = proc_get_status($procData["process"]);
            $elapsed = microtime(true) - $procData["started_at"];

            if (isset($status["running"]) && !$status["running"]) {
                $exitCode = isset($status["exitcode"]) ? (int)$status["exitcode"] : -1;
                $closeCode = closePingProcess($procData, false);

                if ($exitCode < 0) {
                    $exitCode = $closeCode;
                }

                $results[$key] = array(
                    "status" => ($exitCode === 0 ? 1 : 0),
                    "status_text" => ($exitCode === 0 ? "UP" : "DOWN")
                );

                unset($active[$key]);
                continue;
            }

            if ($elapsed >= $timeoutSeconds) {
                closePingProcess($procData, true);

                $results[$key] = array(
                    "status" => 0,
                    "status_text" => "TIMEOUT"
                );

                unset($active[$key]);
            }
        }

        if (!empty($active) || !empty($pending)) {
            usleep(50000);
        }
    }

    return $results;
}

/*
 * Main execution.
 */
$entries = getIpsecPhase2Entries();
$localIps = getLocalInterfaceIps();
$sas = getActiveIpsecSas();
$saMap = buildSaMapByConid($sas);

$phase1Rows = array();
$rows = array();
$jobs = array();

foreach ($entries as $idx => $entry) {
    $sourceIp = findLocalSourceIpForCidr($entry["local_network"], $localIps);
    $targetIp = $entry["pinghost"];

    $conid = (string)$entry["conid"];
    $p1Key = $entry["p1_name"] . "|" . $conid;

    $p1Status = getPhase1Status($conid, $saMap);

    if (!isset($phase1Rows[$p1Key])) {
        $phase1Rows[$p1Key] = array(
            "key" => $p1Key,
            "name" => $entry["p1_name"],
            "ipsec_status" => $p1Status["status"],
            "ipsec_status_text" => $p1Status["status_text"],
            "status" => $p1Status["status"],
            "status_text" => $p1Status["status_text"]
        );
    }

    $probePrecheck = validateProbeConfig($sourceIp, $targetIp, $entry["remote_network"]);

    if ($p1Status["status"] !== 1) {
        $probeStatus = array(
            "status" => 0,
            "status_text" => "SKIPPED_PHASE1_DOWN"
        );
    } elseif ($probePrecheck["status"] !== 9) {
        $probeStatus = $probePrecheck;
    } else {
        $probeStatus = array(
            "status" => 9,
            "status_text" => "PENDING"
        );

        $jobs[$idx] = array(
            "source" => $sourceIp,
            "target" => $targetIp
        );
    }

    $rows[$idx] = array(
        "entry" => $entry,
        "p1_key" => $p1Key,
        "source" => $sourceIp,
        "target" => $targetIp,
        "p1_status" => $p1Status,
        "probe" => $probeStatus
    );
}

$jobResults = runPingJobs($jobs, $PING_TIMEOUT_SECONDS, $PING_CONCURRENCY_LIMIT);

foreach ($jobResults as $idx => $probeResult) {
    if (isset($rows[$idx])) {
        $rows[$idx]["probe"] = $probeResult;
    }
}

foreach ($phase1Rows as $phase1Row) {
    $result->phase1[] = $phase1Row;
}

foreach ($rows as $row) {
    $entry = $row["entry"];
    $p1Status = $row["p1_status"];
    $probeStatus = $row["probe"];

    if ($p1Status["status"] === 1 && $probeStatus["status"] === 1) {
        $finalStatus = 1;
        $finalStatusText = "UP";
    } elseif ($probeStatus["status"] === 2) {
        $finalStatus = 2;
        $finalStatusText = $probeStatus["status_text"];
    } else {
        $finalStatus = 0;
        $finalStatusText = "DOWN";
    }

    if ($entry["p1_name"] === $entry["p2_name"]) {
        $name = $entry["p1_name"];
    } else {
        $name = $entry["p1_name"] . " / " . $entry["p2_name"];
    }

    $key = $row["p1_key"] . "|" .
           $entry["p2_name"] . "|" .
           $entry["local_network"] . "|" .
           $entry["remote_network"];

    $probe = "";

    if ($row["source"] !== "" || $row["target"] !== "") {
        $probe = $row["source"] . " -> " . $row["target"];
    }

    $result->phase2[] = array(
        "p1_key" => $row["p1_key"],
        "key" => $key,
        "name" => $name,
        "local" => $entry["local_network"],
        "remote" => $entry["remote_network"],
        "probe" => $probe,
        "ipsec_status" => $p1Status["status"],
        "ipsec_status_text" => $p1Status["status_text"],
        "lan_ping_status" => $probeStatus["status"],
        "lan_ping_status_text" => $probeStatus["status_text"],
        "status" => $finalStatus,
        "status_text" => $finalStatusText
    );
}

/*
 * JSON output.
 */
$jsonFlags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES;

if (defined("JSON_INVALID_UTF8_SUBSTITUTE")) {
    $jsonFlags = $jsonFlags | JSON_INVALID_UTF8_SUBSTITUTE;
}

$output = json_encode($result, $jsonFlags);

if ($output === false) {
    $output = json_encode(array(
        "error" => "JSON_ENCODE_FAILED",
        "message" => json_last_error_msg()
    ), JSON_PRETTY_PRINT);
}

if ($CACHE_TTL_SECONDS > 0) {
    file_put_contents($CACHE_FILE, $output);
}

echo $output . PHP_EOL;

exit;
