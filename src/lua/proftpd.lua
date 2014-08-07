--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/proftpd.lua
-- Lua module to manage ProFTPd FTP server
-- $Id: proftpd.lua 2849 2014-04-24 17:05:03Z kk $
-- ---------------------------------------------------------------------------
-- This is the "driver" module for ProFTPd FTP server.
-- It must be loaded by the command
--   LC.ftp.load("proftpd")
-- Usually, this should happen at liveconfig.lua (or, if you have a customized
-- module, at custom.lua)
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local LCS = LCS -- import liveconfig global storage
local type = type
local io = io
local os = os
local string = string
local tonumber = tonumber

-- Module declaration
module("proftpd")

-- Exported functions
--   detect()
--   install()
--   uninstall()
--   configure()
--   add()
--   del()
--   lock()
--   unlock()

-- ---------------------------------------------------------------------------
-- getBinaryVersion()
--
-- Return the binary version number from proftpd
-- ---------------------------------------------------------------------------
local function getBinaryVersion(bin)
  -- ProFTPD prints version number to stderr - WTF...?
  local handle = io.popen(bin .. " -v 2>&1", "r")
  local ret = handle:read("*a")
  handle:close()
  local v = string.match(ret, "Version (%d+%.%d+[%.%d%a]*)")
  return v
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect if ProFTPd server is installed. If yes, return a table containing
-- all relevant informations:
--   type          => "proftpd"
--   binname       => file name of the proftpd binary (eg. "/usr/sbin/proftpd")
--   binversion    => binary version (eg. "1.3.3a")
--   pkgname       => name of the package (see below)
--   pkgversion    => package version number (eg. "2.2.3-4+etch11")
--   configpath    => Main configuration path for proftpd
--   configfile    => LiveConfigs' configuration file (snippet)
--   statusfile    => LiveConfigs' status file (containing config version etc.)
--   start_cmd     => command to start ProFTPd
--   stop_cmd      => command to stop ProFTPd
--   reload_cmd    => command to re-load configuration
--   restart_cmd   => command to re-start ProFTPd process
--   ftpd_user     => user running ProFTPD
--
-- If pkgversion is 'nil', then ProFTPd Server was most propably not installed
-- as native distribution package, but compiled/installed manually.
-- ---------------------------------------------------------------------------
function detect()

  local pkg, v, bin

  -- first check for distribution-specific packages
  if LC.distribution.family == "Debian" then
    -- Debian/Ubuntu
    pkg, v = LC.distribution.hasPackage('proftpd-basic', 'proftpd')
  elseif LC.distribution.family == "Gentoo" or LC.distribution.family == "RedHat" or LC.distribution.family == "BSD" or LC.distribution.family == "SUSE" then
    -- Debian/Ubuntu
    pkg, v = LC.distribution.hasPackage('proftpd')
  end
  if pkg == nil then
    -- ProFTPD not found
    return
  end

  LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
  -- get binary version
  if LC.distribution.family == "BSD" then
    bin = "/usr/local/sbin/proftpd"
  else
    bin = "/usr/sbin/proftpd"
  end
  -- get binary version
  local bv = getBinaryVersion(bin)
  if bv == nil then
    LC.log.print(LC.log.DEBUG, "LC.ftp.detect(): Found ProFTPd package '", pkg, "', but binary version is unknown")
    return
  end

  if LC.distribution.family == "Debian" or LC.distribution.family == "Gentoo" then
    -- ok, we have all informations. return data table:
    local data = {
      ["type"]          = "proftpd",
      ["binname"]       = bin,
      ["binversion"]    = bv,
      ["pkgname"]       = pkg,
      ["pkgversion"]    = v,
      ["configpath"]    = "/etc/proftpd",
      ["configfile"]    = "/etc/proftpd/proftpd.conf",
      ["statusfile"]    = "/etc/proftpd/liveconfig.status",
      ["start_cmd"]     = "/etc/init.d/proftpd start",
      ["stop_cmd"]      = "/etc/init.d/proftpd stop",
      ["reload_cmd"]    = "/etc/init.d/proftpd reload",
      ["restart_cmd"]   = "/etc/init.d/proftpd restart",
      ["ftpd_user"]     = "proftpd",
    }
    return data
  elseif LC.distribution.family == "RedHat" or LC.distribution.family == "SUSE" then
    -- ok, we have all informations. return data table:
    local data = {
      ["type"]          = "proftpd",
      ["binname"]       = bin,
      ["binversion"]    = bv,
      ["pkgname"]       = pkg,
      ["pkgversion"]    = v,
      ["configpath"]    = "/etc/proftpd",
      ["configfile"]    = "/etc/proftpd.conf",
      ["statusfile"]    = "/etc/proftpd/liveconfig.status",
      ["start_cmd"]     = "/sbin/service proftpd start",
      ["stop_cmd"]      = "/sbin/service proftpd stop",
      ["reload_cmd"]    = "/sbin/service proftpd reload",
      ["restart_cmd"]   = "/sbin/service proftpd restart",
      ["ftpd_user"]     = "nobody",
    }
    return data
  elseif LC.distribution.family == "BSD" then
    -- ok, we have all informations. return data table:
    local data = {
      ["type"]          = "proftpd",
      ["binname"]       = bin,
      ["binversion"]    = bv,
      ["pkgname"]       = pkg,
      ["pkgversion"]    = v,
      -- Baustelle
      ["configpath"]    = "/etc/proftpd",
      ["configfile"]    = "/etc/proftpd.conf",
      ["statusfile"]    = "/etc/proftpd/liveconfig.status",
      ["start_cmd"]     = "/sbin/service proftpd start",
      ["stop_cmd"]      = "/sbin/service proftpd stop",
      ["reload_cmd"]    = "/sbin/service proftpd reload",
      ["restart_cmd"]   = "/sbin/service proftpd restart",
      ["ftpd_user"]     = "proftpd",
    }
    return data
  end
end

-- ---------------------------------------------------------------------------
-- install(cfg, opts)
--
-- Install LiveConfig configuration files for ProFTPd Server
-- ---------------------------------------------------------------------------
function install(cfg, opts)
  LC.log.print(LC.log.INFO, "Activating management of ProFTPd Server")

  local fh, status, msg
  local configpath  = cfg["configpath"]
  local configfile  = cfg["configfile"]
  local passwdfile  = cfg["configpath"] .. "/passwd"
  local statusfile  = cfg["statusfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    passwdfile = opts.prefix .. passwdfile
    statusfile = opts.prefix .. statusfile
  end

  -- for CentOS5 does not exists configpath...create
  if not LC.fs.is_dir(configpath) then
    LC.fs.mkdir(configpath)
    LC.fs.setperm(configpath, "0755", "root", "root")
  end

  -- back up old default proftpd.conf file (if existing)
  if LC.fs.is_file(configfile) and not LC.fs.is_file(configfile .. ".lcbak") then
    LC.fs.rename(configfile, configfile .. ".lcbak")
  end

  -- create virtual users file (if not existing)
  if not LC.fs.is_file(passwdfile) then
    local fh, msg = io.open(passwdfile .. ".tmp", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", passwdfile .. ".tmp", "' for writing: ", msg)
      return false, "Can't open '" .. passwdfile .. ".tmp" .. "' for writing: " .. msg
    end
    -- adjust owner & permissions - only ProFTPd needs to read this file:
    LC.fs.setperm(passwdfile .. ".tmp", "0460", cfg.ftpd_user, "root")
    fh:close()
    LC.fs.rename(passwdfile .. ".tmp", passwdfile)
  end

  -- write default config file
  configure(cfg, opts)

  return true
end

-- ---------------------------------------------------------------------------
-- uninstall(cfg, opts)
--
-- Remove LiveConfig configuration files from ProFTPd Server
-- ---------------------------------------------------------------------------
function uninstall(cfg, opts)
  LC.log.print(LC.log.INFO, "Disabling management of ProFTPd Server")

  local status, msg
  local configfile  = cfg["configfile"]
  local passwdfile  = cfg["configpath"] .. "/passwd"
  local statusfile  = cfg["statusfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configfile  = opts.prefix .. configfile
    passwdfile = opts.prefix .. passwdfile
    statusfile  = opts.prefix .. statusfile
  end

  -- restore original "proftpd.conf" (if existing...)
  if LC.fs.is_file(configfile .. ".lcbak") then
    LC.fs.rename(configfile .. ".lcbak", configfile)
  end

  -- remove password file
  if LC.fs.is_file(passwdfile) then
      os.remove(passwdfile)
  end

  -- remove status file
  if LC.fs.is_file(statusfile) then
      os.remove(statusfile)
  end

  return true
end


-- ---------------------------------------------------------------------------
-- configure(cfg, opts)
--
-- Configure ProFTPd Server
-- ---------------------------------------------------------------------------
function configure(cfg, opts)

  local fh, status, msg
  local statusfile = cfg["statusfile"]
  local configpath = cfg["configpath"]
  local configfile = cfg["configfile"]
  local v_major, v_minor, v_patch = string.match(cfg.binversion, "^(%d+)%.(%d+)%.(%d+)")
  v_major = tonumber(v_major)
  v_minor = tonumber(v_minor)
  v_patch = tonumber(v_patch)

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    statusfile = opts.prefix .. statusfile
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
  end

  -- create/update SSL certificate file:
  local crtfile, keyfile
  if opts.ssl then
    local sfh
    crtfile = cfg.configpath .. "/ssl-cert.pem"
    keyfile = cfg.configpath .. "/ssl-key.pem"
    if LC.distribution.family == "Debian" then
      crtfile = "/etc/ssl/certs/proftpd.crt"
      keyfile = "/etc/ssl/private/proftpd.key"
    elseif LC.distribution.family == "RedHat" then
      crtfile = "/etc/pki/tls/certs/proftpd.crt"
      keyfile = "/etc/pki/tls/private/proftpd.key"
    end
    sfh, msg = io.open(crtfile, "w")
    LC.fs.setperm(crtfile, "0600", "root", "root")
    if sfh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", crtfile, "' for writing: ", msg)
      return false, "Can't open '" .. crtfile .. "' for writing: " .. msg
    end
    sfh:write(opts.ssl_crt)
    if opts.ssl_ca ~= nil then
      -- append chained certificate:
      sfh:write(opts.ssl_ca)
    end
    sfh:close()

    -- create/update SSL key file:
    sfh, msg = io.open(keyfile, "w")
    LC.fs.setperm(keyfile, "0600", "root", "root")
    if sfh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", keyfile, "' for writing: ", msg)
      return false, "Can't open '" .. keyfile .. "' for writing: " .. msg
    end
    sfh:write(opts.ssl_key)
    sfh:close()
  end

  -- create configuration file
  fh, msg = io.open(configfile .. ".tmp", "w")
  if fh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", configfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. configfile.. ".tmp' for writing: " .. msg
  end
  -- adjust owner & permissions
  LC.fs.setperm(configfile .. ".tmp", "0644", "root", "root")
  LC.liveconfig.writeHeader(fh)

  -- include DSO modules (Debian)
  if LC.fs.is_file("/etc/proftpd/modules.conf") then
    fh:write("# Includes DSO modules\nInclude /etc/proftpd/modules.conf\n")
  end

  fh:write([[

# If set on you can experience a longer connection delay in many cases.
<IfModule mod_ident.c>
IdentLookups                    off
</IfModule>

ServerIdent                     off
ServerName                      "FTP Server"
ServerType                      standalone
DeferWelcome                    off

MultilineRFC2228                on
DefaultServer                   on
ShowSymlinks                    on

TimeoutNoTransfer               600
TimeoutStalled                  600
TimeoutIdle                     1200

DisplayLogin                    welcome.msg
DisplayChdir                    .message true
ListOptions                     "-al"

DenyFilter                      \*.*/

# Use this to jail all users in their homes
DefaultRoot                     ~

# Allow continuation of uploads/downloads
AllowRetrieveRestart            On
AllowStoreRestart               On

# Users require a valid shell listed in /etc/shells to login.
# Use this directive to release that constrain.
RequireValidShell               Off

# Port 21 is the standard FTP port.
Port                            21

]])

  if opts.maxconn and opts.maxconn > 0 then
    fh:write([[
# Limit maximum number of concurrent users
MaxClients                      ]], opts.maxconn, "\n", [[
# Allow 2 more instances to display error message to any more users
# trying to log in
MaxInstances                    ]], tonumber(opts.maxconn) + 2, "\n", [[

]])
  else
    fh:write([[
# Unlimited number of concurrent connections
MaxClients                      none
MaxInstances                    none

]])
  end

  if opts.maxipconn and opts.maxipconn > 0 then
    fh:write("# Limit maximum number of concurrent connections per IP/user\n")
    fh:write("MaxClientsPerHost               ", opts.maxipconn, "\n")
    fh:write("MaxClientsPerUser               ", opts.maxipconn, "\n")
  else
    fh:write("# Unlimited number of concurrent connections per IP/user allowed\n")
    fh:write("MaxClientsPerHost               none\n")
    fh:write("MaxClientsPerUser               none\n")
  end

  if opts.pasvfrom and opts.pasvto then
    fh:write("PassivePorts ", opts.pasvfrom, " ", opts.pasvto, "\n")
  end

  if opts.ssl then
    fh:write([[
<IfModule mod_tls.c>
  TLSEngine On

  # Support both SSLv3 and TLSv1
  TLSProtocol SSLv3 TLSv1

  # Safe ciphers:
  TLSCipherSuite ]], LC.liveconfig.DEFAULT_SSL_CIPHERS, [[

  # Are clients required to use FTP over TLS when talking to this server?
]])
  if opts.sslonly then
    fh:write("TLSRequired on\n")
  else
    fh:write("TLSRequired off\n")
  end

  if v_major > 1 or (v_major == 1 and v_minor > 3) or (v_major == 1 and v_minor == 3 and v_patch >= 3) then
    if opts.sslreuse == false then
      fh:write("TLSOptions NoSessionReuseRequired\n")
    end
  end

  fh:write([[

  # Server's certificate
  TLSRSACertificateFile ]], crtfile, "\n", [[
  TLSRSACertificateKeyFile ]], keyfile, "\n", [[

  # Authenticate clients that want to use FTP over TLS?
  TLSVerifyClient off

</IfModule>

]])
  end

  if LC.distribution.family == "RedHat" then
    fh:write("# Use pam to authenticate (default) and be authoritative\n")
    fh:write("AuthPAMConfig                   proftpd\n")
    fh:write("AuthOrder                       mod_auth_pam.c mod_auth_unix.c mod_auth_file.c\n\n")
  end

  fh:write([[
# Virtual FTP users file
AuthUserFile /etc/proftpd/passwd

# Set the user and group that the server normally runs at.
]])
  if LC.distribution.family == "RedHat" then
    fh:write("User                            nobody\n")
    fh:write("Group                           nobody\n")
  elseif LC.distribution.family == "Gentoo" then
    fh:write("User                            nobody\n")
    fh:write("Group                           nogroup\n")
  else
    fh:write("User                            proftpd\n")
    fh:write("Group                           nogroup\n")
  end

  fh:write([[

# Umask 022 is a good standard umask to prevent new files and dirs
# (second parm) from being group and world writable.
Umask                           022  022
# Normally, we want files to be overwriteable.
AllowOverwrite                  on
]])

  if LC.distribution.family == "Gentoo" then
    fh:write("TransferLog /var/log/xferlog\n")
  else
    fh:write("TransferLog /var/log/proftpd/xferlog\n")
    fh:write("SystemLog   /var/log/proftpd/proftpd.log\n")
  end

  fh:write([[
<IfModule mod_quotatab.c>
QuotaEngine off
</IfModule>

<IfModule mod_ratio.c>
Ratios off
</IfModule>

# Delay engine reduces impact of the so-called Timing Attack described in
# http://security.lss.hr/index.php?page=details&ID=LSS-2004-10-02
# It is on by default.
<IfModule mod_delay.c>
DelayEngine on
</IfModule>
]])
  if LC.distribution.family == "Gentoo" then
    fh:write("<IfModule mod_ctrls.c>\n")
    fh:write("ControlsEngine        off\n")
    fh:write("</IfModule>\n")
  else
    fh:write("<IfModule mod_ctrls.c>\n")
    fh:write("ControlsEngine        off\n")
    fh:write("ControlsMaxClients    2\n")
    fh:write("ControlsLog           /var/log/proftpd/controls.log\n")
    fh:write("ControlsInterval      5\n")
    fh:write("ControlsSocket        /var/run/proftpd/proftpd.sock\n")
    fh:write("</IfModule>\n")
  end
  fh:write([[
<IfModule mod_ctrls_admin.c>
AdminControlsEngine off
</IfModule>

]])

  LC.liveconfig.writeFooter(fh)
  fh:close()

  -- enable configuration
  LC.fs.rename(configfile .. ".tmp", configfile)

  -- update status file
  LC.liveconfig.writeStatus(statusfile, "proftpd", opts.revision, os.date("%Y-%m-%d %H:%M:%S %Z"))

  return true
end

-- ---------------------------------------------------------------------------
-- add(cfg, opts)
--
-- Add virtual FTP account
-- ---------------------------------------------------------------------------
function add(cfg, opts)
  LC.log.print(LC.log.INFO, "Adding/Updating virtual FTP account '", opts.name, "' (ProFTPD)")

  local fhr, fhw, status, msg
  local passwdfile  = cfg["configpath"] .. "/passwd"

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    passwdfile = opts.prefix .. passwdfile
  end

  -- get numeric user id and group id
  local uid = LC.sys.user_exists(opts.user)
  if uid == false then
    return false, "User '" .. opts.user .. "' doesn't exist"
  end
  local gid = LC.sys.group_exists(opts.group)
  if gid == false then
    return false, "Group '" .. opts.group .. "' doesn't exist"
  end

  if not LC.fs.is_file(passwdfile) then
    -- create virtual users file (if not existing)
    fhw, msg = io.open(passwdfile, "a")
    if fhw == nil then
      LC.log.print(LC.log.ERR, "Can't open '", passwdfile, "' for appending: ", msg)
      return false, "Can't open '" .. passwdfile .. "' for appending: " .. msg
    end
    -- adjust owner & permissions - only ProFTPd needs to read this file:
    LC.fs.setperm(passwdfile, "0460", cfg.ftpd_user, "root")
    fhw:close()
  end

  fhr, msg = io.open(passwdfile, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", passwdfile, "' for reading: ", msg)
    return false, "Can't open '" .. passwdfile .. "' for reading: " .. msg
  end

  fhw, msg = io.open(passwdfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", passwdfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. passwdfile.. ".tmp' for writing: " .. msg
  end
  -- adjust owner & permissions - only ProFTPD needs to read this file:
  LC.fs.setperm(passwdfile .. ".tmp", "0460", cfg.ftpd_user, "root")

  -- construct passwd line
  local pwd = opts.password
  if string.sub(pwd, 1, 3) ~= "$1$" or string.len(pwd) ~= 34 then
    -- encrypt password
    pwd = LC.crypt.crypt_md5(pwd)
  end
  local new_line = opts.name .. ":" .. pwd .. ":" .. uid .. ":" .. gid .. "::" .. opts.path .. ":/bin/false"

  -- search/replace existing entry
  local search = "^" .. opts.name .. ":"
  search = string.gsub(search, "%%", "%%%%")
  search = string.gsub(search, "%.", "%%.")
  search = string.gsub(search, "%-", "%%-")
  local line
  local found = false
  while true do
    line = fhr:read()
    if line == nil then break end
--    LC.log.print(LC.log.DEBUG, "Line: '" .. line .. "'")
    if string.find(line, search) ~= nil then
      found = true
--      LC.log.print(LC.log.DEBUG, "  FOUND: '" .. line .. "'")
      fhw:write(new_line)
    else
--      LC.log.print(LC.log.DEBUG, "  not found")
      fhw:write(line)
    end
    fhw:write("\n")
  end

  fhr:close()

  if found == false then
    -- append new entry
    fhw:write(new_line)
    fhw:write("\n")
  end

  fhw:close()

  LC.fs.rename(passwdfile .. ".tmp", passwdfile)

  return true
end

-- ---------------------------------------------------------------------------
-- del(cfg, opts)
--
-- Delete virtual FTP account
-- ---------------------------------------------------------------------------
function del(cfg, opts)
  LC.log.print(LC.log.INFO, "Deleting virtual FTP account (ProFTPD)")

  local fhr, fhw, status, msg
  local passwdfile  = cfg["configpath"] .. "/passwd"

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    passwdfile = opts.prefix .. passwdfile
  end

  if not LC.fs.is_file(passwdfile) then
    -- create virtual users file (if not existing)
    fhw, msg = io.open(passwdfile, "a")
    if fhw == nil then
      LC.log.print(LC.log.ERR, "Can't open '", passwdfile, "' for appending: ", msg)
      return false, "Can't open '" .. passwdfile .. "' for appending: " .. msg
    end
    -- adjust owner & permissions - only ProFTPd needs to read this file:
    LC.fs.setperm(passwdfile, "0460", cfg.ftpd_user, "root")
    fhw:close()
  end

  fhr, msg = io.open(passwdfile, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", passwdfile, "' for reading: ", msg)
    return false, "Can't open '" .. passwdfile .. "' for reading: " .. msg
  end

  fhw, msg = io.open(passwdfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", passwdfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. passwdfile.. ".tmp' for writing: " .. msg
  end
  -- adjust owner & permissions - only ProFTPD needs to read this file:
  LC.fs.setperm(passwdfile .. ".tmp", "0460", cfg.ftpd_user, "root")

  -- search/replace existing entry
  local search = "^" .. opts.name .. ":"
  search = string.gsub(search, "%%", "%%%%")
  search = string.gsub(search, "%.", "%%.")
  search = string.gsub(search, "%-", "%%-")
  local line
  local found = false
  while true do
    line = fhr:read()
    if line == nil then break end
    if string.find(line, search) == nil then
      fhw:write(line, "\n")
    end
  end

  fhr:close()
  fhw:close()

  LC.fs.rename(passwdfile .. ".tmp", passwdfile)

  return true
end

-- ---------------------------------------------------------------------------
-- lock(cfg, users)
--
-- Lock virtual FTP account
-- ---------------------------------------------------------------------------
function lock(cfg, users)
  LC.log.print(LC.log.INFO, "Locking virtual FTP accounts (ProFTPD)")

  local fhr, fhw, status, msg, user, passwd
  local passwdfile  = cfg["configpath"] .. "/passwd"

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    passwdfile = opts.prefix .. passwdfile
  end

  fhr, msg = io.open(passwdfile, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", passwdfile, "' for reading: ", msg)
    return false, "Can't open '" .. passwdfile .. "' for reading: " .. msg
  end

  fhw, msg = io.open(passwdfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", passwdfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. passwdfile.. ".tmp' for writing: " .. msg
  end
  -- adjust owner & permissions - only ProFTPD needs to read this file:
  LC.fs.setperm(passwdfile .. ".tmp", "0460", cfg.ftpd_user, "root")

  while true do
    line = fhr:read()
    if line == nil then break end
    user, passwd = string.match(line, "^([^:]+):(.*)")
    if user and LC.liveconfig.inTable(user, users) then
      -- found user - lock:
      if not string.match(passwd, "^%*") then
        passwd = "*" .. passwd
      end
      fhw:write(user, ":", passwd, "\n")
    else
      -- didn't find, copy full line
      fhw:write(line, "\n")
    end
  end

  fhr:close()
  fhw:close()

  LC.fs.rename(passwdfile .. ".tmp", passwdfile)

  return true
end

-- ---------------------------------------------------------------------------
-- unlock(cfg, users)
--
-- Unlock virtual FTP account
-- ---------------------------------------------------------------------------
function unlock(cfg, users)
  LC.log.print(LC.log.INFO, "Unlocking virtual FTP accounts (ProFTPD)")

  local fhr, fhw, status, msg, user, passwd
  local passwdfile  = cfg["configpath"] .. "/passwd"

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    passwdfile = opts.prefix .. passwdfile
  end

  fhr, msg = io.open(passwdfile, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", passwdfile, "' for reading: ", msg)
    return false, "Can't open '" .. passwdfile .. "' for reading: " .. msg
  end

  fhw, msg = io.open(passwdfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", passwdfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. passwdfile.. ".tmp' for writing: " .. msg
  end
  -- adjust owner & permissions - only ProFTPD needs to read this file:
  LC.fs.setperm(passwdfile .. ".tmp", "0460", cfg.ftpd_user, "root")

  while true do
    line = fhr:read()
    if line == nil then break end
    user, passwd = string.match(line, "^([^:]+):%**(.*)")
    if user and LC.liveconfig.inTable(user, users) then
      -- found user - unlock:
      fhw:write(user, ":", passwd, "\n")
    else
      -- didn't find, copy full line
      fhw:write(line, "\n")
    end
  end

  fhr:close()
  fhw:close()

  LC.fs.rename(passwdfile .. ".tmp", passwdfile)

  return true
end

-- <EOF>----------------------------------------------------------------------
