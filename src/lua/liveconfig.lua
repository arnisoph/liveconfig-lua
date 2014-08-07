--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2014 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/liveconfig.lua
-- LiveConfig resources, written in LUA
-- $Id: liveconfig.lua 2921 2014-06-14 08:25:32Z kk $
-- ---------------------------------------------------------------------------

-- This program is run on every start of LiveConfig. It registeres all
-- LC.* modules and detects the operating system / distribution.
-- If this program can't be run, LiveConfig will not be started.

-- Register all modules (order matters!)
LC.distribution = require("distribution")
LC.hooks = require("hooks")
LC.users = require("users")
LC.cron = require("cron")
LC.web = require("web")
LC.web.load("apache")
LC.web.load("nginx")
LC.dns = require("dns")
LC.dns.load("bind")
LC.smtp = require("smtp")
LC.smtp.load("postfix")
LC.popimap = require("popimap")
LC.popimap.load("dovecot")
LC.db = require("db")
LC.db.load("mysql")
LC.ftp = require("ftp")
LC.ftp.load("proftpd")
LC.ftp.load("vsftpd")

-- default SSL cipher string
-- current value: v2.5.1 from Mozilla OpSec (https://wiki.mozilla.org/Security/Server_Side_TLS)
LC.liveconfig.DEFAULT_SSL_CIPHERS = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:AES128:AES256:RC4-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK"

-- PCI-compliant SSL ciphers, might break some ancient clients:
LC.liveconfig.DEFAULT_SSL_PCI_CIPHERS = "ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:ECDHE-RSA-RC4-SHA:RC4-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA"

-- Define some helper functions

-- ---------------------------------------------------------------------------
-- LC.liveconfig.writeHeader()
-- ---------------------------------------------------------------------------
function LC.liveconfig.writeHeader(fp, comment)
  if comment == nil then comment = '#' end
  fp:write([[
]], comment, [[  _    _          ___           __ _     (R)
]], comment, [[ | |  (_)_ _____ / __|___ _ _  / _(_)__ _
]], comment, [[ | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
]], comment, [[ |____|_|\_/\___|\___\___/_||_|_| |_\__, |
]], comment, [[                                    |___/
]], comment, [[ Copyright (c) 2009-2014 Keppler IT GmbH.
]], comment, [[ ----------------------------------------------------------------------------
]])
end

-- ---------------------------------------------------------------------------
-- LC.liveconfig.writeFooter()
-- ---------------------------------------------------------------------------
function LC.liveconfig.writeFooter(fp, comment)
  if comment == nil then comment = '#' end
  fp:write([[
]], comment, [[ <EOF>-----------------------------------------------------------------------
]])
end

-- ---------------------------------------------------------------------------
-- LC.liveconfig.readStatus()
-- ---------------------------------------------------------------------------
function LC.liveconfig.readStatus(name)
  local fh, errmsg, errno = io.open(name, "r")
  if fh == nil then
    LC.log.print(LC.log.INFO, "Can't open '", name, "' for reading: ", errmsg)
    return nil
  end

  local tab = {}
  local line
  for line in fh:lines() do repeat
    local m = string.match(line, "# LC_CONFIG_ID:%s*([^\n]+)")
    if m then tab.id = m break end
    m = string.match(line, "# LC_CONFIG_REVISION:%s*(%d+)")
    if m then tab.revision = m break end
    m = string.match(line, "# LC_CONFIG_DATE:%s*(%d%d%d%d%-%d%d%-%d%d %d%d:%d%d:%d%d)")
    if m then tab.date = m break end
  until true end
  return tab
end

-- ---------------------------------------------------------------------------
-- LC.liveconfig.writeStatus()
-- ---------------------------------------------------------------------------
function LC.liveconfig.writeStatus(name, id, rev, dat)
  local fh, errmsg, errno = io.open(name, "w")
  if fh == nil then
    LC.log.print(LC.log.INFO, "Can't open '", name, "' for writing: ", errmsg)
    return false
  end

  -- write header
  LC.liveconfig.writeHeader(fh)

  -- write information
  fh:write([[
# This is a status file for the LiveConfig Server Control Panel.
# DO NOT MAKE ANY CHANGES HERE! This file is only maintained by LiveConfig.
#
]])

  -- write id, revision and date
  fh:write('# LC_CONFIG_ID: ', id, '\n')
  fh:write('# LC_CONFIG_REVISION: ', rev, '\n')
  fh:write('# LC_CONFIG_DATE: ', dat, '\n')
  fh:write('#\n')

  -- write footer
  LC.liveconfig.writeFooter(fh)

  fh:close()
  return true
end

-- ---------------------------------------------------------------------------
-- LC.liveconfig.inTable()
-- ---------------------------------------------------------------------------
function LC.liveconfig.inTable(needle, haystack)
  for _,i in pairs(haystack) do
    if (i==needle) then return true end
  end
  return false
end

-- ---------------------------------------------------------------------------
-- LC.liveconfig.updateSysconfig()
-- Update system configuration in /etc/liveconfig/sysconfig
-- ---------------------------------------------------------------------------
function LC.liveconfig.updateSysconfig()
  -- this function is only called by the LiveConfig process!
  local fh, errmsg
  local oldvalues = { }

  -- read current values
  if LC.fs.is_file(LC.liveconfig.sysconfdir .. "/liveconfig/sysconfig") then
    fh, errmsg = io.open(LC.liveconfig.sysconfdir .. "/liveconfig/sysconfig", "r")
    if fh == nil then
      -- if this file exists, it should be readable!
      LC.log.print(LC.log.INFO, "Can't open '" .. LC.liveconfig.sysconfdir .. "/liveconfig/sysconfig' for reading: ", errmsg)
      return false
    end
    local line
    while fh ~= nil do
      line = fh:read()
      if line == nil then break end
      local k,v = string.match(line, "^([^=]*)=(.*)")
      if k ~= nil and v ~= nil then
        oldvalues[k] = v
      end
    end
    fh:close()
  end

  local cfgversion = oldvalues['LC_CFGVERSION']
  if cfgversion == nil then cfgversion = 1 end

  -- check for upgrade tasks!
  if tonumber(cfgversion) < 2 then
    -- fix permissions for web directories
    if not LC.fs.is_file(LC.liveconfig.sysconfdir .. "/liveconfig/sysconfig") then
      -- create preliminary sysconfig file to make "fix-permissions" script work
      fh, errmsg = io.open(LC.liveconfig.sysconfdir .. "/liveconfig/sysconfig", "w")
      if fh == nil then
        LC.log.print(LC.log.INFO, "Can't open '" .. LC.liveconfig.sysconfdir .. "/liveconfig/sysconfig' for writing: ", errmsg)
        return false
      end
      fh:write("LC_WEBROOT=", LC.web.getWebRoot(), "\n")
      fh:write("LC_CFGVERSION=", cfgversion, "\n")
      fh:close()
    end
    cfgversion = 2
  end

  if tonumber(cfgversion) == 2 then
    -- fix postfix virtual_domains file
    LC.log.print(LC.log.INFO, "Running '", LC.liveconfig.libexecdir, "/lcservice.sh check-postfix-domains'")
    local rc = os.execute(LC.liveconfig.libexecdir .. '/lcservice.sh check-postfix-domains')
    -- increase cfg version
    cfgversion = 3
  end

  if tonumber(cfgversion) == 3 then
    -- fix permissions for ~/htdocs/cgi-bin/ (see issue #74)
    -- => now done with rev 5
    -- increase cfg version
    cfgversion = 4
  end

  if tonumber(cfgversion) == 4 then
    -- fix AWStats configuration
    LC.log.print(LC.log.INFO, "Running '", LC.liveconfig.libexecdir, "/lcservice.sh fix-awstats'")
    local rc = os.execute(LC.liveconfig.libexecdir .. '/lcservice.sh fix-awstats')
    -- increase cfg version
    cfgversion = 5
  end

  if tonumber(cfgversion) == 5 then
    -- fix permissions for ~/logs/
    -- create ~/logs/php/
    -- => now done with rev 6
    -- increase cfg version
    cfgversion = 6
  end

  if tonumber(cfgversion) == 6 then
    -- fix permissions for ~/apps/* to work (again) with suPHP
    -- => now done with rev 8
    -- increase cfg version
    cfgversion = 7
  end

  if tonumber(cfgversion) == 7 then
    -- only a change in liveconfig.conf (lccp_socket); done by upgrade script
    -- increase cfg version
    cfgversion = 8
  end

  if tonumber(cfgversion) == 8 then
    -- fix permissions for ~/conf/php5/php.ini (set "immutable" flag)
    LC.log.print(LC.log.INFO, "Running '", LC.liveconfig.libexecdir, "/lcservice.sh fix-permissions'")
    local rc = os.execute(LC.liveconfig.libexecdir .. '/lcservice.sh fix-permissions')
    -- increase cfg version
    cfgversion = 9
  end

  if tonumber(cfgversion) == 9 then
    -- fix permissions for /etc/vsftpd/users (if existing)
    if LC.fs.is_dir("/etc/vsftpd/users") then
      LC.fs.setperm("/etc/vsftpd/users", "0750", "root", "root")
    end
    cfgversion = 10
  end

  if tonumber(cfgversion) == 10 then
    -- fix CustomLog directive in Apache
    -- => modified again with rev 12
    cfgversion = 11
  end

  if tonumber(cfgversion) == 11 then
    -- create /etc/liveconfig/lclogparse.conf if Postfix is managed by LiveConfig (check cfg.revision)
    local cfg = LC.smtp.getConfig("postfix")
    if cfg ~= nil and cfg.revision ~= nil then
      postfix.update_lclogparse(cfg)
      -- (re)start is done with rev 14
    end
    cfgversion = 12
  end

  if tonumber(cfgversion) == 12 then
    -- fix CustomLog directive in Apache
    local cfgfile
    if LC.fs.is_file("/etc/apache2/conf.d/liveconfig") then
      cfgfile = "/etc/apache2/conf.d/liveconfig"
    elseif LC.fs.is_file("/etc/apache2/conf.d/liveconfig.conf") then
      cfgfile = "/etc/apache2/conf.d/liveconfig.conf"
    elseif LC.fs.is_file("/etc/apache2/conf-available/liveconfig.conf") then
      cfgfile = "/etc/apache2/conf-available/liveconfig.conf"
    elseif LC.fs.is_file("/etc/apache2/modules.d/99_liveconfig.conf") then
      cfgfile = "/etc/apache2/modules.d/99_liveconfig.conf"
    elseif LC.fs.is_file("/etc/httpd/conf.d/99_liveconfig.conf") then
      cfgfile = "/etc/httpd/conf.d/99_liveconfig.conf"
    elseif LC.fs.is_file("/usr/local/etc/apache22/extra/liveconfig.conf") then
      cfgfile = "/usr/local/etc/apache22/extra/liveconfig.conf"
    end
    if cfgfile ~= nil then
      LC.log.print(LC.log.INFO, "Patching CustomLog directive in ", cfgfile)
      local rc = os.execute("sed -i -e 's/^CustomLog \"|exec \\//CustomLog \"||\\//g' " .. cfgfile)
    end
    -- increase cfg version
    cfgversion = 13
  end

  if tonumber(cfgversion) == 13 or tonumber(cfgversion) == 14 then
    local cfg = LC.smtp.getConfig("postfix")
    if cfg ~= nil and cfg.revision ~= nil then
      -- eventually (re)start lclogparse:
      if LC.fs.is_file(LC.liveconfig.sysconfdir .. "/liveconfig/lclogparse.conf") then
        os.execute("/etc/init.d/lclogparse restart")
      end
    end
    cfgversion = 15
  end

  -- write new sysconfig file:
  fh, errmsg = io.open(LC.liveconfig.sysconfdir .. "/liveconfig/sysconfig", "w")
  if fh == nil then
    LC.log.print(LC.log.INFO, "Can't open '" .. LC.liveconfig.sysconfdir .. "/liveconfig/sysconfig' for writing: ", errmsg)
    return false
  end

  -- write header
  LC.liveconfig.writeHeader(fh)

  -- write information
  fh:write([[
# This file is automatically created and updated by LiveConfig.
# DO NOT MAKE ANY CHANGES HERE!

]])

  -- write variables:
  fh:write("LC_WEBROOT=", LC.web.getWebRoot(), "\n")
  fh:write("LC_CFGVERSION=", cfgversion, "\n")

  -- write footer
  fh:write("\n")
  LC.liveconfig.writeFooter(fh)

  fh:close()
  return true
end

-- ---------------------------------------------------------------------------
-- LC.liveconfig.update_lclogparse()
-- Update lclogparse(1) configuration in /etc/liveconfig/lclogparse.cfg
-- ---------------------------------------------------------------------------
function LC.liveconfig.update_lclogparse(logfile, rules)
  LC.log.print(LC.log.DEBUG, "update_lclogparse(", logfile, ")")
  if LC.fs.is_file(LC.liveconfig.sysconfdir .. "/liveconfig/lclogparse.conf") then
    -- configuration file already exists
    return
  end

  -- create lclogparse.conf
  local fh, errmsg = io.open(LC.liveconfig.sysconfdir .. "/liveconfig/lclogparse.conf", "w")
  if fh == nil then
    LC.log.print(LC.log.INFO, "Can't open '" .. LC.liveconfig.sysconfdir .. "/liveconfig/lclogparse.conf' for writing: ", errmsg)
    return false
  end

  LC.liveconfig.writeHeader(fh)

  fh:write("!STATUS-FILE:" .. LC.liveconfig.localstatedir .. "/lib/liveconfig/lclogparse.status\n")
  fh:write("!PID-FILE:" .. LC.liveconfig.localstatedir .. "/run/lclogparse.pid\n")

  fh:write("\n", logfile, "\n")
  fh:write(rules, "\n")

  LC.liveconfig.writeFooter(fh)
  fh:close()
  return true

end


-- If "custom.lua" exists, load it:
if (LC.fs.is_file(LC.liveconfig.lua_path .. "/custom.lua")) then
  LC.log.print(LC.log.INFO, "Loading custom Lua settings from '", LC.liveconfig.lua_path, "/custom.lua'")
  dofile(LC.liveconfig.lua_path .. "/custom.lua")
end

-- Detect os/distribution:
LC.distribution.detect()
LC.web.detect()
-- Done.

-- <EOF>----------------------------------------------------------------------
