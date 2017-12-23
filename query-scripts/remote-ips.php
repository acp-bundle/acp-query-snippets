<?php

$whitelist = array('127.0.0.1', "::1", "87.106.243.190");

if (!in_array($_SERVER['REMOTE_ADDR'], $whitelist)) {
    echo "access denied: " . $_SERVER['REMOTE_ADDR'];
    die(0);
}

if (!isset($_POST["token"]) || empty($_POST['token'])) {
	return returnError(1042, "token not found!");
} else {
	if ($_POST["token"] !== "") {
		return returnError(1043, "token mismatch!");
	}
}

$set_xf_db = Array(
    "host"    => "localhost",
    "uname"   => "",
    "pass"    => "",
    "db"      => ""
);

$LANG_ID = 1;

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
					"getUserDataByUserId" => "select `member_id`, `name`, `email`, `members_pass_hash`, `members_pass_salt` from `core_members` where `member_id` = '%s' limit 1;",
					"getUserGroupsFromUserId" => "select `member_group_id`, `mgroup_others` from `core_members` where `member_id` = '%s' limit 1;",
					"getUserDataByUserName" => "select `member_id`, `name`, `email`, `members_pass_hash`, `members_pass_salt` from `core_members` where UPPER(`name`) = UPPER('%s') limit 1;",
					"getUserDataByUserEmail" => "select `member_id`, `name`, `email`, `members_pass_hash`, `members_pass_salt` from `core_members` where UPPER(`email`) = UPPER('%s') limit 1;",
					"getCollabGroupsFromUserId" => "select `member_id`, `collab_id`, `roles` from `collab_memberships` where `collab_id` = '%s' and `member_id` = '%s' limit 1;",
					"getUserIdsFromCollabGroup" => "select `member_id` from `collab_memberships` as c where `collab_id` = '%s' and FIND_IN_SET('%s', c.`roles`) > 0",
					"getUserIdsFromUserGroup" => "select member_id FROM `core_members` WHERE member_group_id=%s OR mgroup_others LIKE '%s%%' OR mgroup_others LIKE '%%%s' OR mgroup_others LIKE '%%,%s,%%' LIMIT 50",
					"getCollabGroupNameById" => "select `name` from `collab_roles` where `id` = '%s' and `collab_id` = '%s'",
					"getUserGroupNameById" => "select `word_default` from `core_sys_lang_words` where `lang_id` = '%s' and `word_app` = 'core' and `word_key` = 'core_group_%s'",
					"getUserFieldContentFromUserId" => "select %s from `core_pfields_content` where member_id=%s"
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
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "User ID was not found.");
					
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
				
				case ("getCollabGroupsFromUserId"):
					if(!isset($_POST['collabId']) || empty($_POST['collabId'])) {
						return returnError(1002, "Required POST parameter not found (collabId)!");
					}
					if(!isset($_POST['userId']) || empty($_POST['userId'])) {
						return returnError(1002, "Required POST parameter not found (userId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getCollabGroupsFromUserId"], filter_var($_POST["collabId"]), filter_var($_POST["userId"]));
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "No role groups found within this collab for the specified user ID.");
					
				case ("getUserIdsFromCollabGroup"):
					if(!isset($_POST['collabId']) || empty($_POST['collabId'])) {
						return returnError(1002, "Required POST parameter not found (collabId)!");
					}
					if(!isset($_POST['groupId']) || empty($_POST['groupId'])) {
						return returnError(1002, "Required POST parameter not found (groupId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserIdsFromCollabGroup"], filter_var($_POST["collabId"]), filter_var($_POST["groupId"]));
					
					try {
						$res = $xf_sql->query($rawquery);
						
						if($res->num_rows === 0 || empty($res[0])) {
							return returnError(4001, "No users were found with the specified role group ID under this collab.");
						}
						
						$ret = Array();
						
						foreach ($res as $row) {
							$ret[] = $row["member_id"];
						}
						
						return returnJson( Array(ids => $ret));
					} catch (Exception $e) {
						return returnError(5001, "SQL Exception: " . $e);
					}
					
					break;
				case ("getUserIdsFromUserGroup"):
					if(!isset($_POST['groupId']) || empty($_POST['groupId'])) {
						return returnError(1002, "Required POST parameter not found (groupId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserIdsFromUserGroup"], filter_var($_POST["groupId"]), filter_var($_POST["groupId"]), filter_var($_POST["groupId"]), filter_var($_POST["groupId"]));
					
					try {
						$res = $xf_sql->query($rawquery);
						
						if($res->num_rows === 0 || empty($res[0])) {
							return returnError(4001, "No users were found with the specified group ID.");
						}
						
						$ret = Array();
						
						foreach ($res as $row) {
							$ret[] = $row["member_id"];
						}
						
						return returnJson( Array(ids => $ret));
					} catch (Exception $e) {
						return returnError(5001, "SQL Exception: " . $e);
					}
					
					break;
				case ("loginUser"):
					// loginUser(String username, String password) <-- returns the userid if successful, -1 if unsuccessful
					if(!isset($_POST['userName']) || empty($_POST['userName'])) {
						return returnError(1002, "Required POST parameter not found (userName)!");
					}
					if(!isset($_POST['plainPass']) || empty($_POST['plainPass'])) {
						return returnError(1002, "Required POST parameter not found (plainPass)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserDataByUserName"], filter_var($_POST["userName"]));
					
					try {
						$res = $xf_sql->query($rawquery);
						
						if($res->num_rows === 0) {
							// PS: You can return a specified error ID from here instead to differentiate between wrong pass, wrong username etc.
							return returnJson(array("member_id" => '-1'));
						}
						
						//`members_pass_hash`, `members_pass_salt`
						
						//echo crypt(filter_var($_POST["plainPass"]), $res[0]["members_pass_salt"], );
						
						$hashvars = explode("$", $res[0]["members_pass_hash"]);
						$provided = crypt(filter_var($_POST["plainPass"]), sprintf("$%s$%s$%s", $hashvars[1], $hashvars[2], $res[0]["members_pass_salt"]));
						
						if (compareHashes($res[0]["members_pass_hash"], $provided)) {
							return returnJson(array("member_id" => $res[0]["member_id"]));
						}
						
						return returnJson(array("member_id" => '-1'));
						
					} catch (Exception $e) {
						return returnError(5001, "SQL Exception: " . $e);
					}
					
					break;
				case ("getCollabGroupNameById"):
					if(!isset($_POST['groupId']) || empty($_POST['groupId'])) {
						return returnError(1002, "Required POST parameter not found (groupId)!");
					}
					if(!isset($_POST['collabId']) || empty($_POST['collabId'])) {
						return returnError(1002, "Required POST parameter not found (collabId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getCollabGroupNameById"], filter_var($_POST["groupId"]), filter_var($_POST["collabId"]));
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "No role group found with the specified ID under this collab.");

				case ("getUserGroupNameById"):
					if(!isset($_POST['groupId']) || empty($_POST['groupId'])) {
						return returnError(1002, "Required POST parameter not found (groupId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserGroupNameById"], $LANG_ID, filter_var($_POST["groupId"]));
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "No user group found with the specified ID");

				case ("getUserFieldContentFromUserId"):
					if(!isset($_POST['fieldId']) || empty($_POST['fieldId'])) {
						return returnError(1002, "Required POST parameter not found (fieldId)!");
					}
					if(!isset($_POST['userId']) || empty($_POST['userId'])) {
						return returnError(1002, "Required POST parameter not found (userId)!");
					}
					
					$rawquery = sprintf($QUERY_MAP["getUserFieldContentFromUserId"], filter_var($_POST["fieldId"]), filter_var($_POST["userId"]));
					
					return $xf_sql->runIPSQuerySingleResult($rawquery, "No field content found for this fieldId for the specified user ID.");
					
				default:
					return returnError(1003, "Specified IPS Query method not found!");
            }
            break;
		default:
			return returnError(1000, "No action found!");
    }
} else {
	return returnError(1000, "No action found!");
}


/**
 * From IPS 4 Login system.
 * Compare hashes in fixed length, time constant manner.
 *
 * @param	string	$expected	The expected hash
 * @param	string	$provided	The provided input
 * @return	boolean
 */
function compareHashes($expected, $provided)
{
	if ( !is_string( $expected ) || !is_string( $provided ) || $expected === '*0' || $expected === '*1' || $provided === '*0' || $provided === '*1' ) // *0 and *1 are failures from crypt() - if we have ended up with an invalid hash anywhere, we will reject it to prevent a possible vulnerability from deliberately generating invalid hashes
	{
		return FALSE;
	}

	$len = strlen( $expected );
	if ( $len !== strlen( $provided ) )
	{
		return FALSE;
	}

	$status = 0;
	for ( $i = 0; $i < $len; $i++ )
	{
		$status |= ord( $expected[ $i ] ) ^ ord( $provided[ $i ] );
	}
	
	return $status === 0;
}


?>