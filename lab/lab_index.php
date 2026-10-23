<?php
// php2shell lab page: reflects the sprayed $_POST values back hex-dumped.
// The reclaim receipt: fire-request sprays land in the freed BG(unserialize)/
// BG(serialize) context blocks; the decode/encode writes into those blocks
// mutate the reflected bytes in place (n++, var_push pointer stores).
header('Content-Type: text/plain');
echo "PID=" . getmypid() . " SAPI=" . php_sapi_name() . "\n";
foreach (array('s', 't') as $k) {
    if (!isset($_POST[$k])) { continue; }
    $arr = $_POST[$k];
    if (!is_array($arr)) { echo "$k: not-array\n"; continue; }
    echo "$k count=" . count($arr) . "\n";
    for ($i = 0; $i < min(3, count($arr)); $i++) {
        $v = $arr[$i];
        echo "$k\[$i\] len=" . strlen($v) . " head=" . bin2hex(substr($v, 0, 64)) . "\n";
        if ($k === 't') {
            // t strings reclaim the 64-byte serialize context: val[16..24]
            // overlays nNextFreeElement(+40)/pDestructor(+48) = val[16]/val[24];
            // php_add_var_hash does n++ at +0x38 = val[32].
            echo "  +0x38-region=" . bin2hex(substr($v, 24, 24)) . "\n";
        } else {
            // s strings reclaim the 8208-byte unserialize context.
            // +56 used_slots / +64 next / +72.. data[] = val[32]/val[40]/val[48..]
            echo "  hdr-region=" . bin2hex(substr($v, 0, 96)) . "\n";
            echo "  entries-region=" . bin2hex(substr($v, 24 + 32, 96)) . "\n";
        }
    }
}
echo "SESSION_BYTES=" . (isset($_SESSION) ? strlen(session_encode()) : -1) . "\n";
echo "LABOK\n";
