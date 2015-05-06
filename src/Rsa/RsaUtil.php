<?php

namespace Rsa;

/**
 * Data encrypt and decrypt util. Use OpenSSL (https://www.openssl.org/)
 * The Rsa Key will be Base64 String. It's can saved anywhere.
 * User: alan
 * Date: 2015/05/05
 * Time: 下午 05:06
 */

class RsaUtil {

	private static $DN;
	private static $PKEY_CONFIG;
	private $uuid;
	private $keystoresPath;
	private $certKey;
	private $enCryptKey;
	private $deCryptKey;
	private $keyDays = 15; // Rsa Key valid day

	private function uuid() {
		return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
			mt_rand(0, 0xffff), mt_rand(0, 0xffff),
			mt_rand(0, 0xffff),
			mt_rand(0, 0x0fff) | 0x4000,
			mt_rand(0, 0x3fff) | 0x8000,
			mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
		);
	}

	private function defaultKeyStorePath() {
		return "./keystores/";
	}

	private function defaultDnConfig() {
		return array(
			"countryName" => 'TW',
			"stateOrProvinceName" => '.',
			"localityName" => 'Taipei',
			"organizationName" => 'Company',
			"organizationalUnitName" => '.',
			"commonName" => ".",
			"emailAddress" => 'xxxxx@gmail.com',
		);
	}

	private function defaultPKeyConfig() {
		return array(
			"digest_alg" => "sha256",
			"private_key_bits" => 4096, // about data length
			"private_key_type" => OPENSSL_KEYTYPE_RSA,
		);
	}

	public function __construct() {
		$this->uuid = $this->uuid();
		$this->keystoresPath = $this->defaultKeyStorePath();
		$this->setConfig();
	}

	/**
	 * RSA Key stores path
	 *
	 * @author  Alan
	 * @date    2015-05-05
	 * @version [1.0.0]
	 * @param   string     $path
	 */
	public function setKeyStorePath($path = "") {
		$this->keystoresPath = $path;
		return $this;
	}

	public function getKeyStorePath() {
		return $this->keystoresPath;
	}

	/**
	 * RSA Key config
	 *
	 * @author  Alan
	 * @date    2015-05-05
	 * @version [1.0.0]
	 * @param   array      $Dn   [description]
	 * @param   array      $PKey [description]
	 */
	public function setConfig($Dn = array(), $PKey = array()) {
		self::$DN = $Dn;
		if (empty(self::$DN)) {
			self::$DN = $this->defaultDnConfig();
		}
		self::$PKEY_CONFIG = $PKey;
		if (empty(self::$PKEY_CONFIG)) {
			self::$PKEY_CONFIG = $this->defaultPKeyConfig();
		}
		return $this;
	}

	/**
	 * Generate RSA encrypt and decrypt key
	 */
	public function generate() {
		if (!is_dir($this->keystoresPath) && !file_exists($this->keystoresPath)) {
			mkdir($this->keystoresPath, 0777, true);
		}

		$pemFile = sprintf('%1$s/%2$s_private.pem', $this->keystoresPath, $this->uuid);
		$derFile = sprintf('%1$s/%2$s_public.der', $this->keystoresPath, $this->uuid);
		$encPemFile = sprintf('%1$s/%2$s_enc_private.pem', $this->keystoresPath, $this->uuid);
		$certFile = sprintf('%1$s/%2$s_cert.csr', $this->keystoresPath, $this->uuid);

		$privKey = openssl_pkey_new(self::$PKEY_CONFIG);
		$csr = openssl_csr_new(self::$DN, $privKey);
		$sscert = openssl_csr_sign($csr, null, $privKey, $this->keyDays);
		openssl_csr_export($csr, $csrOut);
		openssl_x509_export($sscert, $certOut);
		openssl_pkey_export($privKey, $privateKey);

		file_put_contents($pemFile, $privateKey);
		file_put_contents($certFile, $csrOut);
		exec("openssl x509 -req -in $certFile -out $derFile -outform der -signkey $pemFile");

		$count = 0;
		$wait = true;
		while ($wait && $count < 5) {
			if (file_exists($derFile)) {
				$wait = false;
			}
			$count++;
			sleep(1);
		}
		$this->certKey = base64_encode($certOut);
		$this->enCryptKey = base64_encode(file_get_contents($derFile));
		$this->deCryptKey = base64_encode($privateKey);
		return $this;
	}

	public function setDate($date) {
		$this->date = $date;
		return $this;
	}

	public function fileRevert() {
		$this->certKey = '';
		$this->enCryptKey = '';
		$this->deCryptKey = '';

		$pemFile = sprintf('%1$s/%2$s_private.pem', $this->keystoresPath, $this->uniqueId);
		$derFile = sprintf('%1$s/%2$s_public.der', $this->keystoresPath, $this->uniqueId);
		$certFile = sprintf('%1$s/%2$s_cert.csr', $this->keystoresPath, $this->uniqueId);

		if (!file_exists($pemFile) | !file_exists($derFile) | !file_exists($certFile)) {
			return;
		}

		$pem = file_get_contents($pemFile);
		$der = file_get_contents($derFile);
		$cert = file_get_contents($certFile);

		$this->certKey = base64_encode($cert);
		$this->enCryptKey = base64_encode($der);
		$this->deCryptKey = base64_encode($pem);
	}

	public function getUuid() {
		return $this->uuid;
	}

	/**
	 * Base64 Cert String
	 *
	 * @author  Alan
	 * @date    2015-05-06
	 * @version [1.0.0]
	 * @return  Base64 String
	 */
	public function getCertKey() {
		return $this->certKey;
	}

	/**
	 * Base64 Public Key String
	 *
	 * @author  Alan
	 * @date    2015-05-06
	 * @version [1.0.0]
	 * @return  Base64 String
	 */
	public function getEnCryptKey() {
		return $this->enCryptKey;
	}

	/**
	 * Base64 Private Key String
	 *
	 * @author  Alan
	 * @date    2015-05-06
	 * @version [1.0.0]
	 * @return  Base64 String
	 */
	public function getDeCryptKey() {
		return $this->deCryptKey;
	}

	/**
	 * Check RSA key isn't exist
	 * @return bool
	 */
	public function isExist() {
		if (!empty($this->enCryptKey) && !empty($this->deCryptKey) && !empty($this->certKey)) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Check RSA key within valid date
	 * @param $cert
	 * @return bool
	 */
	public function verifyKey($cert) {
		$now = date('U');
		$data = openssl_x509_parse($cert);
		$validFrom = $data['validFrom_time_t'];
		$validTo = $data['validTo_time_t'];

		if ($now >= $validFrom && $now <= $validTo) {
			return true;
		}

		return false;
	}

	/**
	 * Check RSA key is valid
	 * @param $cert
	 * @param $privateKey
	 * @return bool
	 */
	public function checkKey($cert, $privateKey) {
		return openssl_x509_check_private_key($cert, $privateKey);
	}

	/**
	 * Encrypt text
	 *
	 * @author  Alan
	 * @date    2015-05-06
	 * @version [1.0.0]
	 * @param   string     $text
	 * @return  Base64 String
	 */
	public function encrypt($text = "") {
		$certKey = base64_decode($this->getCertKey());

		if (empty($certKey)) {
			return false;
		}

		openssl_public_encrypt($text, $encrypt, $certKey);
		return base64_encode($encrypt);
	}

	/**
	 * Decrypt text
	 *
	 * @author  Alan
	 * @date    2015-05-06
	 * @version [1.0.0]
	 * @param   string     $enText [description]
	 * @return  string
	 */
	public function decrypt($enText = "") {
		$enText = base64_decode($enText);
		$deCryptKey = base64_decode($this->getDeCryptKey());

		if (empty($deCryptKey)) {
			return false;
		}

		openssl_private_decrypt($enText, $decrypted, $deCryptKey);
		return $decrypted;
	}

}
