<?php
$test1 = 1;
$test2 = 2;
function factorial($n) {
    // Conditional statement
    if ($n <= 1) {
        return 1; //7  //+
    } else {
        return $n * factorial($n - 1); //8 //+
    }
}
$test3 = 3;
function checkEvenOrOdd($num) { //+
    // Conditional statement
    if ($num % 2 == 0) {
        return "even"; //9 //+
    } else {
        return "odd"; //10
    }
}
$test4 =4;
?>