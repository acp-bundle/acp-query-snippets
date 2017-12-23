<?php

$whitelist = array('127.0.0.1', "::1", "87.106.243.190");

if (!in_array($_SERVER['REMOTE_ADDR'], $whitelist)) {
    echo "access denied: " . $_SERVER['REMOTE_ADDR'];
    die(0);
}

if (isset($_POST["action"]) && !empty($_POST['action'])) {

    switch (filter_var($_POST["action"])) {
            
        case 'storage_query':
			if (!isset($_POST["server_key"]) || empty($_POST['server_key'])) {
				return "server_key not found!";
			}
			
            switch (filter_var($_POST["server_key"])) {
				
				case ("getUserDataByUserId"):
					if(!isset($_POST['userId']) || empty($_POST['userId'])) {
						return returnError(1002, "Required POST parameter not found (userId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserDataByUserId"], filter_var($_POST["userId"]));
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "User ID was not found.");
					
				default:
					return returnError(1003, "Specified IPS Query server_key not found!");
            }
            break;
		default:
			return returnError(1000, "No action found!");
    }
} else {
	return returnError(1000, "No action found!");
}
