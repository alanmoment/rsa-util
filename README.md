# RsaUtil

Data encrypt and decrypt util. Use OpenSSL (https://www.openssl.org/).

The Rsa Key will be Base64 String. It's can saved anywhere.

# Usage

Add this code to your composer.json

	{
	    "repositories": [
	        {
	            "type": "git",
	            "url": "https://github.com/alanmoment/rsa-util.git"
	        }
	    ],
	    "require": {
	        "alanmoment/rsa-util": "dev-master"
	    },
	    "minimum-stability": "dev",
		"autoload": {
	        "classmap": [
	            "vendor/alanmoment"
	        ]
	    }    
	}

Do it

	$ composer install

# Reference

Look at project example code.