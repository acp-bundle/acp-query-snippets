<?php

$whitelist = array('127.0.0.1', "::1");

$token = "";

if (!in_array($_SERVER['REMOTE_ADDR'], $whitelist)) {
    echo "access denied: " . $_SERVER['REMOTE_ADDR'];
    die(0);
}

if ($_REQUEST['token'] != $token) {
    echo "access denied: wrong token";
    die(0);
}

$set_xf_db = Array(
    "host"    => "localhost",
    "uname"   => "",
    "pass"    => "",
    "db"      => ""
);

class MySQL
{
    public $MySQLiObj;
    public $lastSQLQuery;
    public $lastSQLStatus;
    public function __construct($server, $user, $password, $db, $port="3306")
    {
        $this->MySQLiObj = new \mysqli($server, $user, $password, $db, $port);
        if(mysqli_connect_errno())
        {
            echo "Can't connect to database!";
            die();
        }
        //Characterset UTF-8
        $this->query("SET NAMES utf8");
    }
    public function __destruct()
    {
        $this->MySQLiObj->close();
    }
    public function query($sqlQuery, $resultset = false)
    {
        $this->lastSQLQuery = $sqlQuery;
        //this->doLog($sqlQuery);
        $result = $this->MySQLiObj->query($sqlQuery);
        if($resultset == true)
        {
            if($result == false)
            {
                $this->lastSQLStatus = false;
            }
            else
            {
                $this->lastSQLStatus = true;
            }
            return $result;
        }
        $return = $this->makeArrayResult($result);
        return $return;
    }
    public function escapeString($value)
    {

        return $this->MySQLiObj->real_escape_string($value);

    }
    public function lastSQLError()
    {
        return $this->MySQLiObj->error;
    }
    private function makeArrayResult($ResultObj)
    {
        if($ResultObj === false)
        {
            $this->lastSQLStatus = false;
            return false;
        }
        else if($ResultObj === true)
        {
            $this->lastSQLStatus = true;
            return true;
        }
        else if($ResultObj->num_rows == 0)
        {
            $this->lastSQLStatus = true;
            return array();
        }
        else
        {
            $array = array();
            while($line = $ResultObj->fetch_array(MYSQLI_ASSOC))
            {
                array_push($array, $line);
            }
            $this->lastSQLStatus = true;
            return $array;
        }
    }
	
	public function runIPSQuerySingleResult($rawquery, $errormsg) {
	
		try {
			$res = $this->query($rawquery);
			
			if($res->num_rows === 0 || empty($res[0])) {
				return returnError(4001, $errormsg);
			}
			
			return returnJson($res[0]);
		} catch (Exception $e) {
			return returnError(5001, "SQL Exception: " . $e);
		}
	}
}

function returnError($errorId, $message) {
	return returnJson(array('errorId' => $errorId, 'message' => $message));
}

function returnJson($jsonObject) {
	echo json_encode($jsonObject);
}

if (isset($_POST["action"]) && !empty($_POST['action'])) {
	
	$QUERY_MAP = array(
					"getUserDataByUserId" => "SELECT * FROM xf_user WHERE user_id=%s LIMIT 1;",
					"getUserGroupsFromUserId" => "SELECT user_group_id FROM xf_user_group_relation WHERE user_id=%s;",
					"getUserDataByUserName" => "SELECT * FROM xf_user WHERE UPPER(`username`) = UPPER('%s') LIMIT 1;",
					"getUserDataByUserEmail" => "SELECT * FROM xf_user WHERE UPPER(`email`) = UPPER('%s') LIMIT 1;",
					"getUserIdsFromUserGroup" => "SELECT user_id FROM xf_user_group_relation WHERE user_group_id=%s;",
					"getUserGroupNameById" => "SELECT title FROM xf_user_group WHERE user_group_id=%s",
					"getUserFieldContentFromUserId" => "SELECT `field_value` FROM `xf_user_field_value` WHERE user_id=%s AND field_id=%s"
					);

    switch (filter_var($_POST["action"])) {
            
        case 'ips_query':
			if (!isset($_POST["method"]) || empty($_POST['method'])) {
				return returnError(1001, "IPS Query method not found!");
			}
			
            $xf_sql = new MySQL($set_xf_db["host"], $set_xf_db["uname"], $set_xf_db["pass"], $set_xf_db["db"]);

            switch (filter_var($_POST["method"])) {
				
				case ("getUserDataByUserId"):
					if(!isset($_POST['userId']) || empty($_POST['userId'])) {
						return returnError(1002, "Required POST parameter not found (userId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserDataByUserId"], filter_var($_POST["userId"]));
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "User ID was not found.");
					
				case ("getUserGroupsFromUserId"):
					if(!isset($_POST['userId']) || empty($_POST['userId'])) {
						return returnError(1002, "Required POST parameter not found (userId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserGroupsFromUserId"], filter_var($_POST["userId"]));

                                        try {
                                                $res = $xf_sql->query($rawquery);

                                                $ret = Array();

                                                foreach ($res as $row) {
                                                        $ret[] = $row["user_group_id"];
                                                }

                                                return returnJson( Array(ids => $ret));
                                        } catch (Exception $e) {
                                                return returnError(5001, "SQL Exception: " . $e);
                                        }

				case ("getUserDataByUserName"):
					if(!isset($_POST['userName']) || empty($_POST['userName'])) {
						return returnError(1002, "Required POST parameter not found (userName)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserDataByUserName"], filter_var($_POST["userName"]));
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "User with the specified username was not found.");
					
				case ("getUserDataByUserEmail"):
					if(!isset($_POST['userEmail']) || empty($_POST['userEmail'])) {
						return returnError(1002, "Required POST parameter not found (userEmail)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserDataByUserEmail"], filter_var($_POST["userEmail"]));
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "User with the specified email was not found.");
				
					break;
				case ("getUserIdsFromUserGroup"):
					if(!isset($_POST['groupId']) || empty($_POST['groupId'])) {
						return returnError(1002, "Required POST parameter not found (groupId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserIdsFromUserGroup"], filter_var($_POST["groupId"]));
					
					try {
						$res = $xf_sql->query($rawquery);
						
						if($res->num_rows === 0 || empty($res[0])) {
							return returnError(4001, "No users were found with the specified group ID.");
						}
						
						$ret = Array();
						
						foreach ($res as $row) {
							$ret[] = $row["user_id"];
						}
						
						return returnJson( Array(ids => $ret));
					} catch (Exception $e) {
						return returnError(5001, "SQL Exception: " . $e);
					}
					
					break;
				case ("loginUser"):
					// To be done
					break;

				case ("getUserGroupNameById"):
					if(!isset($_POST['groupId']) || empty($_POST['groupId'])) {
						return returnError(1002, "Required POST parameter not found (groupId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserGroupNameById"], filter_var($_POST["groupId"]));
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "No user group found with the specified ID");

				case ("getUserFieldContentFromUserId"):
					if(!isset($_POST['fieldId']) || empty($_POST['fieldId'])) {
						return returnError(1002, "Required POST parameter not found (fieldId)!");
					}
					if(!isset($_POST['userId']) || empty($_POST['userId'])) {
						return returnError(1002, "Required POST parameter not found (userId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserFieldContentFromUserId"], filter_var($_POST["userId"]), filter_var($_POST["fieldId"]));
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "No field content found for this fieldId for the specified user ID.");
					
				default:
					return returnError(1003, "Specified XF Query method not found!");
            }
            break;
		default:
			return returnError(1000, "No action found!");
    }
} else {
	return returnError(1000, "No action found!");
}

?>
