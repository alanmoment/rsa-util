<?php

require __DIR__ . '/vendor/autoload.php';

use Rsa\RsaUtil;

$RsaUtil = new RsaUtil();
$RsaUtil->setKeyStorePath("./keystores/");
$encrypt = $RsaUtil->generate()->encrypt("I am test data.");
echo $encrypt;

$decrypted = $RsaUtil->decrypt($encrypt);
echo $decrypted;