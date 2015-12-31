<?php

//App: Test and document
$secretCode = 'f0d1ba666a6cbed3';
$privateKey = 'MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQCr2zjTtCQyJmRc
XSO4IaO2LqJZQPOoSY/5Suzf6DbM5/6tsgBlVki1LlrgFmW/cO7HdeeaGvPbjQ5k
wE7Vw1ymgRA2KPV25mWkljwEmKm2WuPcL4r89KnSKOWWdyTC9hikCmbdHELwhO+m
ZjchlOtEqWgL9ehF7f2nrwBG3Fcopbkj9hjEW5xj3VvoAQ5Q1qowUR0vOk78OBxx
rGhz43VIx9k4q57tofRlAiSws3s5AZWiK5Uu+a8ZGRin+oiesUrVg3Y235F6ne
XhNT7jcwUa9rMAKfUovEPfrXJgg76c5ntyGBDfmHuQnrJ0MZMow14YUtpUJ/j88w
PpzGIJ1f2jrPYCIypH5aen/GvbXE2tqs5U7P6+NodqFvlYSER9Y8u2GxbxefaOz0
4h4KDWUOPI7Ucgw0J9pNOKRGtsBez4eHVIdFAAQXSL0aWH/2o16D+spnrLE4+3CF
Seywkb6LvuuC/ttN+LZU9g2rq6kCgYEAwLduz9WOmnQi++0FKLfW4UNpTt+5fdmu
m2m0ehmwAXIVdGKwNwWRMpHTviIBnI3PQIIexMIGcrHW70NRV1RKgKxNfI0uUGAS
j0oab18N0L53D32AJ7sW0ispPJVxi1ZCkIuMCgzTsskQnpnTqgxfMFF7llkEUeXH
XCyh5zlgPY8CgYEAo/ybnw2rHAUsuyocAxfkFPsQAKbLOMFEidJ/F7pN9PKO73Yk
SxVEKkMpTl2I9upU8YpjT85+ogGkac6zugvrZDJTrFsF/1DZBb0Tpr5TGTsjZxB6
nvUBMlfR9gFI/IunOsF5ItzkTkvb99pjFLA+QeNTdSiuJ66XOvKW40z8pUkCgYEA
sZ6fOFkZRQvzToRnM9804ovSHIshGHgwcTccy0ivqrVuRsXKqfuslpJHOT94gsVF
FqyXFTvK251Df2RpLPcYb73e8QPigtv5Xy2qbamLPzC85X8DRhsubmivahJHA2hu
k3C6kmy+FVMxySv4JQugFBWVtb23uI/yjebpFgcQx8sCgYEA2bx/ej7dY6kGsPGP
AgfEYVbTS3YRC30gzpo9QsklqWS/btQi0JsdFlOgHau8XrPpoIDuWlQ6jwtbK/aY
4APC746ry95yz3N6oH7rND61ufaApReGlSV7zCPC5N97ymJEt9p0G0Xil0S0Ms8/
LABVOpAYoJBwxaaNnHlyPBpuYtg=';

set_include_path(get_include_path() . PATH_SEPARATOR . './phpseclib1.0.0');
include('Crypt/RSA.php');

$token = @$_POST['token'];
$result = 1;
if ($token) {
	$rsa = new Crypt_RSA();
	$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
	$rsa->loadKey($privateKey); //private key
	
	$ciphertext = base64_decode($token);
	$plaintext = $rsa->decrypt($ciphertext);

	if ($plaintext) {
		$plaintextJson = json_decode($plaintext);
		if ($plaintextJson) {
			$appId = $plaintextJson->appId;
			$azStackUserID = $plaintextJson->azStackUserID;
			$timestamp = $plaintextJson->timestamp;
			$code = $plaintextJson->code;

			//verify code = md5(appId . "_" . timestamp . "_" . secretCode)
			//		to make sure request is from AZStack
			$code2 = md5($appId . "_" . $timestamp . "_" . $secretCode);
			if ($code2 == $code) {
				error_log('Authenticate request from AZStack: ' . $plaintext);

				//check user credentials
				$userCredentialsValid = true; //you can check in your Database, etc

				if ($userCredentialsValid) {
					$result = 0;
				}
			} else {
				error_log('NOT VALID CODE!!!! Authenticate request from AZStack: ' . $plaintext);
			}
		}
	}
}

//respond AZStack
echo json_encode(array('result' => $result));
