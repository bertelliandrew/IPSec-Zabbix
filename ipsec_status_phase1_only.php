<?php

/*
 * Monitoramento de IPsec no pfSense para Zabbix.
 *
 * Versão: somente Phase 1
 *
 * Este script valida apenas o status da Phase 1/IKE SA.
 * Não executa ping, não valida Phase 2 por tráfego e não depende
 * do campo Automatically ping host.
 *
 * Status:
 * 1 = UP
 * 0 = DOWN
 */

require_once("/etc/inc/globals.inc");
require_once("/etc/inc/functions.inc");
require_once("/etc/inc/config.inc");
require_once("ipsec.inc");

$result = new stdClass();
$result->phase1 = array();
$result->phase2 = array();

/*
 * Lê caminhos da configuração do pfSense com compatibilidade entre versões.
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
 * Garante que entradas do config.xml sejam tratadas como lista.
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
        isset($value["remote-gateway"])
    ) {
        return array($value);
    }

    return $value;
}

/*
 * Descobre todas as Phase 1 habilitadas.
 */
function getConfiguredPhase1Entries() {
    $entries = array();

    if (!function_exists("ipsec_enabled") || !ipsec_enabled()) {
        return $entries;
    }

    /*
     * Método preferencial: mapa nativo do pfSense.
     */
    if (function_exists("ipsec_map_config_by_id")) {
        $cmap = ipsec_map_config_by_id();

        if (is_array($cmap)) {
            foreach ($cmap as $ikeid => $tunnel) {
                if (!isset($tunnel["p1"]) || !is_array($tunnel["p1"])) {
                    continue;
                }

                $p1 = $tunnel["p1"];

                if (isset($p1["disabled"])) {
                    continue;
                }

                $name = isset($p1["descr"]) && trim($p1["descr"]) !== ""
                    ? trim($p1["descr"])
                    : "IKEID_" . $ikeid;

                $remoteGateway = isset($p1["remote-gateway"])
                    ? (string)$p1["remote-gateway"]
                    : "";

                $conid = function_exists("ipsec_conid")
                    ? ipsec_conid($p1)
                    : "con" . $ikeid;

                $entries[] = array(
                    "ikeid" => (string)$ikeid,
                    "conid" => (string)$conid,
                    "name" => (string)$name,
                    "remote_gateway" => (string)$remoteGateway,
                    "key" => (string)$name . "|" . (string)$conid
                );
            }
        }

        if (count($entries) > 0) {
            return $entries;
        }
    }

    /*
     * Fallback: leitura direta da configuração.
     */
    $phase1Raw = getConfigPathCompat("ipsec/phase1", array());
    $phase1List = ensureList($phase1Raw);

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

        $name = isset($p1["descr"]) && trim($p1["descr"]) !== ""
            ? trim($p1["descr"])
            : "IKEID_" . $ikeid;

        $remoteGateway = isset($p1["remote-gateway"])
            ? (string)$p1["remote-gateway"]
            : "";

        $conid = function_exists("ipsec_conid")
            ? ipsec_conid($p1)
            : "con" . $ikeid;

        $entries[] = array(
            "ikeid" => (string)$ikeid,
            "conid" => (string)$conid,
            "name" => (string)$name,
            "remote_gateway" => (string)$remoteGateway,
            "key" => (string)$name . "|" . (string)$conid
        );
    }

    return $entries;
}

/*
 * Lê as SAs ativas do IPsec no pfSense/strongSwan.
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
 * Indexa SAs pelo con-id.
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
 * Verifica se a Phase 1/IKE SA está estabelecida.
 */
function getPhase1Status($conid, $saMap) {
    $conid = (string)$conid;

    if (!isset($saMap[$conid])) {
        return array(
            "status" => 0,
            "status_text" => "DOWN",
            "ike_state" => "NOT_FOUND"
        );
    }

    $ikesa = $saMap[$conid];

    $state = isset($ikesa["state"])
        ? strtoupper((string)$ikesa["state"])
        : "";

    if ($state === "ESTABLISHED") {
        return array(
            "status" => 1,
            "status_text" => "UP",
            "ike_state" => $state
        );
    }

    return array(
        "status" => 0,
        "status_text" => "DOWN",
        "ike_state" => $state
    );
}

/*
 * Execução principal.
 */
$phase1Entries = getConfiguredPhase1Entries();
$sas = getActiveIpsecSas();
$saMap = buildSaMapByConid($sas);

foreach ($phase1Entries as $entry) {
    $status = getPhase1Status($entry["conid"], $saMap);

    $result->phase1[] = array(
        "key" => $entry["key"],
        "name" => $entry["name"],
        "remote_gateway" => $entry["remote_gateway"],
        "ikeid" => $entry["ikeid"],
        "conid" => $entry["conid"],
        "ipsec_status" => $status["status"],
        "ipsec_status_text" => $status["status_text"],
        "ike_state" => $status["ike_state"],
        "status" => $status["status"],
        "status_text" => $status["status_text"]
    );
}

/*
 * Mantido vazio para preservar estrutura de JSON.
 * Nesta versão, Phase 2 não é monitorada.
 */
$result->phase2 = array();

/*
 * Geração da saída JSON.
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

echo $output . PHP_EOL;

exit;