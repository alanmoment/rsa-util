<?php

use Rsa\RsaUtil;

class RsaUtilTest extends \PHPUnit_Framework_TestCase {

	private $rsaUtil;
	private $certKey;
	private $enCryptKey;
	private $deCryptKey;
	private $testString = "I am test data.";

	public function __construct() {
		$this->rsaUtil = new RsaUtil();
	}

	public function testKeystoresPath() {
		$path = __DIR__ . "/../keystores/";
		$this->rsaUtil->setKeyStorePath($path);
		$this->assertEquals($this->rsaUtil->getKeyStorePath(), $path);
	}

	public function testNewObject() {
		$uuid = $this->rsaUtil->getUuid();
		$this->assertRegExp('/[a-z0-9]+\-[a-z0-9]+\-[a-z0-9]+\-[a-z0-9]+\-[a-z0-9]+/', $uuid);
	}

	/**
	 * Generate Rsa Key and decrypt string after encrypted
	 *
	 * @author  Alan
	 * @date    2015-05-06
	 * @version [1.0.0]
	 */
	public function testGenerateRsaKey() {
		$this->rsaUtil->generate();
		$this->assertTrue($this->rsaUtil->isExist());

		$certKey = base64_decode($this->rsaUtil->getCertKey());
		$this->assertTrue($this->rsaUtil->verifyKey($certKey));

		$encrypt = $this->rsaUtil->encrypt($this->testString);
		$decrypted = $this->rsaUtil->decrypt($encrypt);
		$this->assertSame($this->testString, $decrypted);
	}

}