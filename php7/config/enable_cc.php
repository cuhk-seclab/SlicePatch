<?php
$do_cc = true; //+ temp disable

if (isset($_SERVER['SCRIPT_FILENAME']) && !empty($_SERVER['SCRIPT_FILENAME'])) {
    $bn = basename($_SERVER['SCRIPT_FILENAME'], ".php");
    if (strpos($_SERVER['SCRIPT_FILENAME'], 'webgrind') !== false || strpos($_SERVER['SCRIPT_FILENAME'], 'enable_cc.php') !== false || strpos($_SERVER['SCRIPT_FILENAME'], 'export_cc.php') !== false || strpos($_SERVER['SCRIPT_FILENAME'], 'clean.php') !== false || strpos($_SERVER['SCRIPT_FILENAME'], 'remove.php') !== false  || strpos($_SERVER['SCRIPT_FILENAME'], 'patch.php') !== false || strpos($_SERVER['SCRIPT_FILENAME'], 'slice.php') !== false) {
        $do_cc = false;
    }
}
if (file_exists("/tmp/start_test.dat") && $do_cc) {

    date_default_timezone_set("Asia/Hong_Kong");
    $coverage_dpath = "/dev/shm/coverages/"; //__DIR__;
    if (!is_dir($coverage_dpath)){
        mkdir($coverage_dpath, 0777, true);
    }
    $tarut = (isset($_SERVER['SCRIPT_FILENAME']) && !empty($_SERVER['SCRIPT_FILENAME'])) ? $_SERVER['SCRIPT_FILENAME'] : $_SERVER['REQUEST_URI'];
    $tarut_dirname = realpath(dirname($tarut));
    $tarut_dirname = str_replace("/","+",$tarut_dirname );

    $tarut_basename = basename($tarut, ".php");

    $tarut_name = $tarut_dirname . "+" . $tarut_basename;
    //echo "hidy-ho neighbor " . $tarut_dirname . "+" . $tarut_basename . "\n";

    xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE);
    function get(&$var, $default=null) {
        return isset($var) ? $var : $default;
    }
    function milliseconds() {
        $mt = explode(' ', microtime());
        return ((int)$mt[1]) * 1000 + ((int)round($mt[0] * 1000));
    }
    function mdy_name() {
        $dt = new DateTime("now", new DateTimeZone('Asia/Hong_Kong'));
        return $dt->format('m-d-Y_Hi_') . strval(milliseconds());
    }
    function end_coverage()
    {
        global $tarut_name;
        global $coverage_dpath;
        global $coverage_saved;

        // Prevent duplicate coverage saves
        if (isset($coverage_saved) && $coverage_saved) {
            return;
        }
        $coverage_saved = true;

        // $coverageName = $coverage_dpath . $tarut_name . "_" . strval(milliseconds()) . ".cc";
        $coverageName = $coverage_dpath . $tarut_name . "_" . mdy_name() . ".cc";
        $jsonCoverageFPath = $coverageName . ".json";

        try {
            xdebug_stop_code_coverage(false);

            $cur_cc_jdata = xdebug_get_code_coverage();
            $json_data = json_encode($cur_cc_jdata);
            file_put_contents($jsonCoverageFPath, $json_data);

        } catch (Exception $ex) {
	        echo "ERROR encountered " . $ex . "\n";
            file_put_contents($coverage_dpath."exceptions.log", $ex, FILE_APPEND);
        } finally {

        }
    }

    class coverage_dumper
    {
        function __destruct()
        {
            try {
                end_coverage();
            } catch (Exception $ex) {
                echo str($ex);
            }
        }
    }

    // Register shutdown function as backup for fatal errors
    register_shutdown_function('end_coverage');
    
    $_coverage_dumper = new coverage_dumper();
}