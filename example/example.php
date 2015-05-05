<?php

require_once __DIR__ . '/../src/RsaUtil.php';

use Rsa\RsaUtil;

$RsaUtil = new RsaUtil();
$RsaUtil->setKeyStorePath("./example/keystores/");
$RsaUtil->generate();

$certKey = base64_decode($RsaUtil->getCertKey());

while (!$RsaUtil->isExist()) {
	sleep(1);
}

if ($RsaUtil->verifyKey($certKey)) {
	echo $RsaUtil->getUuid() . " is valid.\n";
} else {
	echo $RsaUtil->getUuid() . " is invalid.\n";
}

$encryptKey = base64_decode($RsaUtil->getEnCryptKey());
openssl_public_encrypt("I'm data.", $encrypt, $certKey);

$encrypt = base64_encode($encrypt);
echo "I'm encrypt data: $encrypt\n";

$decryptKey = base64_decode($RsaUtil->getDeCryptKey());
openssl_private_decrypt(base64_decode($encrypt), $decrypted, $decryptKey);
echo "I'm decrypt data: $decrypted\n";