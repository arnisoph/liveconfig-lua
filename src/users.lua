--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/users.lua
-- User accounts management
--
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local os = os
local string = string

-- Module declaration
module("users")

-- Exported functions
--   addUser()
--   addGroup()
--   delUser()
--   delGroup()
--   chPasswd()
--   chShell()
--   lock()
--   unlock()

-- ---------------------------------------------------------------------------
-- addUser()
--
-- Add a new system account
-- - the group must already exist
-- - "shell" parameter must be "sh", "scponly" or "nologin" - any other value
--   defaults to "/bin/false"
-- ---------------------------------------------------------------------------
function addUser(user, group, home, shell)

  LC.log.print(LC.log.INFO, "Adding system account '", user, "'")

  if shell == "sh" then
    shell = "/bin/bash"
  elseif shell == "scponly" then
    if LC.fs.is_file("/usr/bin/rssh") then
      shell = "/usr/bin/rssh"
    else
      shell = "/usr/bin/scponly"
    end
  elseif shell == "nologin" then
    if LC.fs.is_file("/sbin/nologin") then
      shell = "/sbin/nologin"
    else
      shell = "/usr/sbin/nologin"
    end
  else
    shell = "/bin/false"
  end

  if LC.distribution.family == "Debian" then
    useradd = "/usr/sbin/useradd -d " .. home .. " -g " .. group .. " " .. "-s " .. shell .. " " .. user
  elseif LC.distribution.family == "SunOS" then
    useradd = "useradd -d " .. home .. " -g " .. group .. " " .. "-s " .. shell .. " " .. user
  elseif LC.distribution.family == "RedHat" then
    useradd = "/usr/sbin/useradd -d " .. home .. " -M -g " .. group .. " " .. "-s " .. shell .. " " .. user
  elseif LC.distribution.family == "SUSE" then
    useradd = "useradd -d " .. home .. " -g " .. group .. " " .. "-s " .. shell .. " " .. user
  elseif LC.distribution.family == "BSD" then
    useradd = "pw useradd " .. user .. " -d " .. home .. " -g" .. group .. " -s" .. shell .. " -c ''"
  elseif LC.distribution.family == "Gentoo" then
    useradd = "/usr/sbin/useradd -d " .. home .. " -g " .. group .. " " .. "-s " .. shell .. " " .. user
  end

  local rc = LC.exec(useradd)

  if rc ~= 0 then
    return false, "Error while adding user '" .. user .. "' (exit code: " .. rc .. ")"
  end

  if LC.hooks then
    LC.hooks.check("LC.users.addUser", user, group, home, shell)
  end

  return true

end

-- ---------------------------------------------------------------------------
-- delUser()
--
-- Delete a system account
-- ---------------------------------------------------------------------------
function delUser(user)

  LC.log.print(LC.log.INFO, "Deleting system account '", user, "'")

  -- run hooks *before* the user is actually deleted!
  if LC.hooks then
    LC.hooks.check("LC.users.delUser", user)
  end

  if LC.sys.user_exists(user) then
    -- only try to delete if user really still exists

    -- if 'killall' command is available, kill all processes by this user:
    if LC.fs.is_file('/usr/bin/killall') then
      LC.exec('/usr/bin/killall -s KILL -u ' .. user)
    end

    if LC.distribution.family == "Debian" then
      userdel = "/usr/sbin/userdel -f " .. user
    elseif LC.distribution.family == "SunOS" then
      userdel = "userdel " .. user
    elseif LC.distribution.family == "RedHat" then
      userdel = "/usr/sbin/userdel -f " .. user
    elseif LC.distribution.family == "SUSE" then
      userdel = "/usr/sbin/userdel -f " .. user
    elseif LC.distribution.family == "BSD" then
      userdel = "pw userdel " .. user
    elseif LC.distribution.family == "Gentoo" then
      userdel = "/usr/sbin/userdel -f " .. user
    end

    local rc = LC.exec(userdel)

    if rc ~= 0 and rc ~= 2048 then
      LC.log.print(LC.log.INFO, "Error while deleting user '" .. user .. "' (exit code: " .. rc .. ")")
    end

    if LC.sys.user_exists(user) then
      LC.log.print(LC.log.INFO, "User was not deleted!")
      return false
    end
  end

  return true

--[[
  if LC.distribution.family == "RedHat" then
    os.remove("/var/spool/mail/" .. data.user)
  end
]]--

end

-- ---------------------------------------------------------------------------
-- addGroup()
--
-- Add a new system group
-- ---------------------------------------------------------------------------
function addGroup(group)

  if LC.distribution.family == "Debian" then
    groupadd = "/usr/sbin/groupadd " .. group
  elseif LC.distribution.family == "SunOS" then
    groupadd = "groupadd " .. group
  elseif LC.distribution.family == "RedHat" then
    groupadd = "/usr/sbin/groupadd " .. group
  elseif LC.distribution.family == "SUSE" then
    groupadd = "groupadd " .. group
  elseif LC.distribution.family == "BSD" then
    groupadd = "pw groupadd -n " .. group
  elseif LC.distribution.family == "Gentoo" then
    groupadd = "/usr/sbin/groupadd " .. group
  end

  local rc = LC.exec(groupadd)

  if rc ~= 0 then
    LC.log.print(LC.log.ERR, "Error while adding group '" .. group .. "' (exit code: " .. rc .. ")");
    return false
  end

  if LC.hooks then
    LC.hooks.check("LC.users.addGroup", group)
  end

  return true

end

-- ---------------------------------------------------------------------------
-- delGroup()
--
-- Delete a system group
-- ---------------------------------------------------------------------------
function delGroup(group)

  if LC.sys.group_exists(group) then
    -- only try to delete if group really still exists
    if LC.distribution.family == "Debian" then
      groupdel = "/usr/sbin/groupdel " .. group
    elseif LC.distribution.family == "SunOS" then
      groupdel = "groupdel " .. group
    elseif LC.distribution.family == "RedHat" then
      groupdel = "/usr/sbin/groupdel " .. group
    elseif LC.distribution.family == "SUSE" then
      groupdel = "/usr/sbin/groupdel " .. group
    elseif LC.distribution.family == "BSD" then
      groupdel = "pw groupdel " .. group
    elseif LC.distribution.family == "Gentoo" then
      groupdel = "/usr/sbin/groupdel " .. group
    end

    local rc = LC.exec(groupdel)

    if rc ~= 0 then
      LC.log.print(LC.log.ERR, "Error while deleting group '" .. group .. "' (exit code: " .. rc .. ")");
      return false
    end
  end

  if LC.hooks then
    LC.hooks.check("LC.users.delGroup", group)
  end

  return true

end

-- ---------------------------------------------------------------------------
-- chPasswd()
--
-- Change password of a local system account
-- ---------------------------------------------------------------------------
function chPasswd(user, passwd)

  if user == "root" then
    return false
  end

  if string.match(passwd, "^%$1%$[%w%.%/%$]+$") and LC.fs.is_file("/bin/sed") and LC.fs.is_file("/etc/shadow") then
    -- pre-hashed MD5 password. try to replace directly in /etc/shadow
    passwd = string.gsub(passwd, "/", "\\/")
    LC.mutex.lock("users.chPasswd")
    local sedcmd = "/bin/sed -i -e 's/^" .. user .. ":[^:]/" .. user .. ":" .. passwd .. "/' /etc/shadow"
    os.execute(sedcmd)
    LC.mutex.unlock("users.chPasswd")
    return true
  end

  local e = LC.expect.new()
  --e:log(true)
  local successful = false
  -- change password for a normal user:
  local st, msg = e:spawn("/usr/bin/passwd", { user } )
  if not st then
    LC.log.print(LC.log.ERR, "Can't execute /usr/bin/passwd: " .. msg)
    return false
  end

  local function send_password(m)
    -- send new password (with '\n' at the end!)
    e:send(passwd .. "\n")
  end

  local function pwd_success(m)
    successful = true
  end

  local list = {
    { match  = "(?i)(new UNIX password:)|(New Password:)",
      action = send_password },
    { match  = "(?i)(updated successfully)|(Password changed.)|(Password unchanged)|(updated successfully)",
      action = pwd_success },
  }

  e:expect(list, 5)

  if (successful) then
    return true
  else
    return false
  end

end

-- ---------------------------------------------------------------------------
-- chShell()
--
-- Change shell of a local system account
-- ---------------------------------------------------------------------------
function chShell(user, shell)

  if user == "root" then
    return false
  end

  if shell == "sh" then
    shell = "/bin/bash"
  elseif shell == "scponly" then
    if LC.fs.is_file("/usr/bin/rssh") then
      shell = "/usr/bin/rssh"
    else
      shell = "/usr/bin/scponly"
    end
  elseif shell == "nologin" then
    if LC.fs.is_file("/sbin/nologin") then
      shell = "/sbin/nologin"
    else
      shell = "/usr/sbin/nologin"
    end
  else
    shell = "/bin/false"
  end

  if LC.distribution.family == "BSD" then
    usermod = "pw usermod " .. user .. " -s " .. shell
  else
    usermod = "/usr/sbin/usermod -s " .. shell .. " " .. user
  end

  local rc = LC.exec(usermod)

  if rc ~= 0 then
    LC.log.print(LC.log.ERR, "Error while updating shell for user '" .. user .. "' (exit code: " .. rc .. ")")
    return false, "Error while updating shell for user '" .. user .. "' (exit code: " .. rc .. ")"
  end

  if LC.hooks then
    LC.hooks.check("LC.users.chShell", user, shell)
  end

  return true

end

-- ---------------------------------------------------------------------------
-- lock()
--
-- Lock a user account
-- ---------------------------------------------------------------------------
function lock(user)

  local cmd

  if LC.distribution.family == "Debian" or LC.distribution.family == "RedHat" or LC.distribution.family == "SUSE" or LC.distribution.family == "Gentoo" then
    cmd = "/usr/sbin/usermod -L " .. user
  elseif LC.distribution.family == "BSD" then
    cmd = "pw lock " .. user
  else
    -- not supported...
    return false, "Distribution not supported"
  end

  local rc = LC.exec(cmd)

  if rc ~= 0 then
    return false, "Error while locking user '" .. user .. "' (exit code: " .. rc .. ")"
  end

  if LC.hooks then
    LC.hooks.check("LC.users.lock", user)
  end

  return true
end

-- ---------------------------------------------------------------------------
-- unlock()
--
-- Unlock a user account
-- ---------------------------------------------------------------------------
function unlock(user)
  local cmd

  if LC.distribution.family == "Debian" or LC.distribution.family == "RedHat" or LC.distribution.family == "SUSE" or LC.distribution.family == "Gentoo" then
    cmd = "/usr/sbin/usermod -U " .. user
  elseif LC.distribution.family == "BSD" then
    cmd = "pw unlock " .. user
  else
    -- not supported...
    return false, "Distribution not supported"
  end

  local rc = LC.exec(cmd)

  if rc ~= 0 then
    return false, "Error while locking user '" .. user .. "' (exit code: " .. rc .. ")"
  end

  if LC.hooks then
    LC.hooks.check("LC.users.lock", user)
  end

  return true
end

-- <EOF>----------------------------------------------------------------------
