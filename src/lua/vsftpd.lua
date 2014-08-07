--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/vsftpd.lua
-- Lua module to manage vsftpd FTP server
-- $Id: vsftpd.lua 2849 2014-04-24 17:05:03Z kk $
-- ---------------------------------------------------------------------------
-- This is the "driver" module for vsftpd FTP server.
-- It must be loaded by the command
--   LC.ftp.load("vsftpd")
-- Usually, this should happen at liveconfig.lua (or, if you have a customized
-- module, at custom.lua)
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local LCS = LCS -- import liveconfig global storage
local type = type
local io = io
local os = os
local pairs = pairs
local string = string
local tonumber = tonumber

-- Module declaration
module("vsftpd")

-- Exported functions
--   detect()
--   install()
--   uninstall()
--   configure()
--   init()
--   add()
--   del()
--   lock()
--   unlock()

LC.mutex.lock("vsftpd")
if LCS.vsftpd == nil then
  LCS.vsftpd = {
    config = { },
    managed = false
  }
end
LC.mutex.unlock("vsftpd")

-- ---------------------------------------------------------------------------
local function find_dbload()
  if LC.fs.is_file("/usr/bin/db_load") then
    return("/usr/bin/db_load")
  elseif LC.fs.is_file("/usr/bin/db4.6_load") then
    return("/usr/bin/db4.6_load")
  elseif LC.fs.is_file("/usr/bin/db4.7_load") then
    return("/usr/bin/db4.7_load")
  elseif LC.fs.is_file("/usr/bin/db4.8_load") then
    return("/usr/bin/db4.8_load")
  else
    LC.log.print(LC.log.ERR, "Can't find 'db_load' utility - did you install the db4-util package?")
    return
  end
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect if vsftpd server is installed. If yes, return a table containing
-- all relevant informations:
--   type          => "vsftpd"
--   binname       => file name of the vsftpd binary (eg. "/usr/sbin/vsftpd")
--   binversion    => binary version (eg. "1.3.3a")
--   pkgname       => name of the package (see below)
--   pkgversion    => package version number (eg. "2.2.3-4+etch11")
--   configpath    => Main configuration path for vsftpd
--   configfile    => LiveConfigs' configuration file (snippet)
--   statusfile    => LiveConfigs' status file (containing config version etc.)
--   start_cmd     => command to start vsftpd
--   stop_cmd      => command to stop vsftpd
--   reload_cmd    => command to re-load configuration
--   restart_cmd   => command to re-start vsftpd process
--
-- If pkgversion is 'nil', then vsftpd Server was most propably not installed
-- as native distribution package, but compiled/installed manually.
-- ---------------------------------------------------------------------------
function detect()

  local pkg, v

  -- first check for distribution-specific packages
  if LC.distribution.family == "Debian" or LC.distribution.family == "RedHat" or LC.distribution.family == "SUSE" or LC.distribution.family == "Gentoo" then
    -- Debian/Ubuntu, RedHat/CentOS
    pkg, v = LC.distribution.hasPackage('vsftpd')
  end
  if pkg == nil then
    -- vsftpd not found
    return
  end

  LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
  local bin = "/usr/sbin/vsftpd"
  
  if LC.distribution.family == "Debian" or LC.distribution.family == "SUSE" then
    -- ok, we have all informations. return data table:
    local cfg = {
      ["type"]          = "vsftpd",
      ["binname"]       = bin,
      ["binversion"]    = v,
      ["pkgname"]       = pkg,
      ["pkgversion"]    = v,
      ["configpath"]    = "/etc/vsftpd",
      ["configfile"]    = "/etc/vsftpd.conf",
      ["statusfile"]    = "/etc/vsftpd/liveconfig.status",
    }
    if LC.fs.is_file("/etc/init.d/vsftpd") then
      cfg["start_cmd"]    = "/etc/init.d/vsftpd start"
      cfg["stop_cmd"]     = "/etc/init.d/vsftpd stop"
      cfg["reload_cmd"]   = "/etc/init.d/vsftpd reload"
      cfg["restart_cmd"]  = "/etc/init.d/vsftpd restart"
    else
      cfg["start_cmd"]    = "/sbin/service vsftpd start"
      cfg["stop_cmd"]     = "/sbin/service vsftpd stop"
      cfg["reload_cmd"]   = "/sbin/service vsftpd restart"
      cfg["restart_cmd"]  = "/sbin/service vsftpd restart"
    end
    LCS.vsftpd.config = cfg
    return cfg
  elseif LC.distribution.family == "RedHat" or LC.distribution.family == "Gentoo" then
    -- ok, we have all informations. return data table:
    local cfg = {
      ["type"]          = "vsftpd",
      ["binname"]       = bin,
      ["binversion"]    = v,
      ["pkgname"]       = pkg,
      ["pkgversion"]    = v,
      ["configpath"]    = "/etc/vsftpd",
      ["configfile"]    = "/etc/vsftpd/vsftpd.conf",
      ["statusfile"]    = "/etc/vsftpd/liveconfig.status",
      ["start_cmd"]     = "/etc/init.d/vsftpd start",
      ["stop_cmd"]      = "/etc/init.d/vsftpd stop",
      ["reload_cmd"]    = "/etc/init.d/vsftpd reload",
      ["restart_cmd"]   = "/etc/init.d/vsftpd restart",
    }
    LCS.vsftpd.config = cfg
    return cfg
  end
end

-- ---------------------------------------------------------------------------
-- install(cfg, opts)
--
-- Install LiveConfig configuration files for vsftpd Server
-- ---------------------------------------------------------------------------
function install(cfg, opts)
  LC.log.print(LC.log.INFO, "Activating management of vsftpd Server")

  local fh, status, msg
  local configpath  = cfg["configpath"]
  local configfile  = cfg["configfile"]
  local passwdfile  = cfg["configpath"] .. "/passwd.db"
  local pamfile     = "/etc/pam.d/vsftpd-lc"
  local statusfile  = cfg["statusfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    passwdfile = opts.prefix .. passwdfile
    pamfile    = opts.prefix .. pamfile
    statusfile = opts.prefix .. statusfile
  end

  -- if configpath doesn't exist... create:
  if not LC.fs.is_dir(configpath) then
    LC.fs.mkdir(configpath)
  end

  -- back up old default vsftpd.conf file (if existing)
  if LC.fs.is_file(configfile) and not LC.fs.is_file(configfile .. ".lcbak") then
    LC.fs.rename(configfile, configfile .. ".lcbak")
  end

  -- create directory for virtual user configuration files:
  if not LC.fs.is_dir(configpath .. "/users") then
    LC.fs.mkdir(configpath .. "/users")
    LC.fs.setperm(configpath .. "/users", 750, "root", "root")
  end

  -- create PAM file (if not existing)
  if not LC.fs.is_file(pamfile) then
    local fh, msg = io.open(pamfile .. ".tmp", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", pamfile .. ".tmp", "' for writing: ", msg)
      return false, "Can't open '" .. pamfile .. ".tmp" .. "' for writing: " .. msg
    end
    -- adjust owner & permissions
    LC.fs.setperm(pamfile .. ".tmp", 644, "root", "root")
    -- write configuration
    fh:write("#%PAM-1.0\n")
    LC.liveconfig.writeHeader(fh)

    if LC.distribution.family == "RedHat" then
      -- RedHat/CentOS:
      if LC.fs.is_file("/etc/pam.d/password-auth") then
        fh:write([[
session    optional     pam_keyinit.so    force revoke
auth       sufficient   pam_userdb.so db=/etc/vsftpd/passwd crypt=crypt
auth       required     pam_listfile.so item=user sense=deny file=/etc/vsftpd/ftpusers onerr=succeed
auth       required     pam_shells.so
auth       include      password-auth
account    sufficient   pam_userdb.so db=/etc/vsftpd/passwd crypt=crypt
account    include      password-auth
session    required     pam_loginuid.so
session    include      password-auth

]])
      else
        -- CentOS 5 has no "password-auth" -> use "system-auth"!
        fh:write([[
session    optional     pam_keyinit.so    force revoke
auth       sufficient   pam_userdb.so db=/etc/vsftpd/passwd crypt=crypt
auth       required     pam_listfile.so item=user sense=deny file=/etc/vsftpd/ftpusers onerr=succeed
auth       required     pam_shells.so
auth       include      system-auth
account    sufficient   pam_userdb.so db=/etc/vsftpd/passwd crypt=crypt
account    include      system-auth
session    required     pam_loginuid.so
session    include      system-auth

]])
      end
    else
      -- Default:
      fh:write([[
# PAM configuration for vsftpd with virtual users
# Maintained by LiveConfig

# Virtual account is sufficient, try local account as fallback:
auth    required   pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed
auth    sufficient pam_userdb.so db=/etc/vsftpd/passwd crypt=crypt
auth    required   pam_unix.so

# Local account is sufficient, permit any (virtual) account as fallback:
account sufficient pam_unix.so
account required pam_permit.so

]])
    end

    LC.liveconfig.writeFooter(fh)
    fh:close()
    LC.fs.rename(pamfile .. ".tmp", pamfile)
  end

  -- write config file
  configure(cfg, opts)

  return true
end

-- ---------------------------------------------------------------------------
-- uninstall(cfg, opts)
--
-- Remove LiveConfig configuration files from vsftpd Server
-- ---------------------------------------------------------------------------
function uninstall(cfg, opts)
  LC.log.print(LC.log.INFO, "Disabling management of vsftpd Server")

  local status, msg
  local configpath  = cfg["configpath"]
  local configfile  = cfg["configfile"]
  local passwdfile  = cfg["configpath"] .. "/passwd.db"
  local pamfile     = "/etc/pam.d/vsftpd-lc"
  local statusfile  = cfg["statusfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    passwdfile = opts.prefix .. passwdfile
    pamfile    = opts.prefix .. pamfile
    statusfile = opts.prefix .. statusfile
  end

  -- restore original "vsftpd.conf" (if existing...)
  if LC.fs.is_file(configfile .. ".lcbak") then
    LC.fs.rename(configfile .. ".lcbak", configfile)
  end

  -- remove passwd file
  if LC.fs.is_file(passwdfile) then
    status, msg = os.remove(passwdfile)
    if status == nil then
      LC.log.print(LC.log.ERR, "Deletion of '", passwdfile, "' failed: ", msg)
    end
  end

  -- remove PAM file
  if LC.fs.is_file(pamfile) then
    status, msg = os.remove(pamfile)
    if status == nil then
      LC.log.print(LC.log.ERR, "Deletion of '", pamfile, "' failed: ", msg)
    end
  end

  -- remove status file
  if LC.fs.is_file(statusfile) then
    status, msg = os.remove(statusfile)
    if status == nil then
      LC.log.print(LC.log.ERR, "Deletion of '", statusfile, "' failed: ", msg)
    end
  end

  -- remove per-user configuration files:
  if LC.fs.is_dir(configpath .. "/users") then
    os.execute("rm -rf \"" .. configpath .. "/users\"")
  end

  return true
end


-- ---------------------------------------------------------------------------
-- configure(cfg, opts)
--
-- Configure vsftpd Server
-- ---------------------------------------------------------------------------
function configure(cfg, opts)

  local fh, status, msg
  local statusfile = cfg["statusfile"]
  local configpath = cfg["configpath"]
  local configfile = cfg["configfile"]
  local passwdfile  = cfg["configpath"] .. "/passwd.db"
  local pamfile     = "/etc/pam.d/vsftpd-lc"
  local v_major, v_minor = string.match(cfg.binversion, "^(%d+)%.(%d+)")
  v_major = tonumber(v_major)
  v_minor = tonumber(v_minor)

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    statusfile = opts.prefix .. statusfile
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    passwdfile = opts.prefix .. passwdfile
    pamfile    = opts.prefix .. pamfile
  end

  -- create/update SSL certificate file:
  local crtfile, keyfile
  if opts.ssl then
    local sfh
    crtfile = cfg.configpath .. "/ssl-cert.pem"
    keyfile = cfg.configpath .. "/ssl-key.pem"
    if LC.distribution.family == "Debian" then
      crtfile = "/etc/ssl/certs/vsftpd.crt"
      keyfile = "/etc/ssl/private/vsftpd.key"
    elseif LC.distribution.family == "RedHat" then
      crtfile = "/etc/pki/tls/certs/vsftpd.crt"
      keyfile = "/etc/pki/tls/private/vsftpd.key"
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
  LC.fs.setperm(configfile .. ".tmp", 640, "root", "root")
  LC.liveconfig.writeHeader(fh)

  fh:write([[
# vsftpd Configuration
# Managed by LiveConfig

# Run standalone?
listen=YES

# Hide software & version in banner string
ftpd_banner=FTP Server

# If this server is IPv6 capable and you want to enable vsftpd at the
# IPv6 interfaces, please comment out the "listen" command above, and
# uncomment this line.
# LiveConfig will provide a GUI for this in one of the next releases.
#listen_ipv6=YES

# Allow local users to log in (important for "real" accounts)
local_enable=YES

# Allow uploads :)
write_enable=YES

# umask for uploads:
local_umask=022

# display local time instead of GMT:
use_localtime=YES

# Log uploads/downloads
xferlog_enable=YES

# Make sure PORT transfer connections originate from port 20 (ftp-data).
connect_from_port_20=YES

# chroot() users after login:
chroot_local_user=YES

# PAM service for LiveConfig-managed vsftpd:
pam_service_name=vsftpd-lc

# disable anonymous users:
anonymous_enable=NO

# allow virtual users:
guest_enable=YES
virtual_use_local_privs=YES
user_config_dir=/etc/vsftpd/users

]])

  if opts.maxconn and opts.maxconn > 0 then
    fh:write("# Limit maximum number of concurrent connections\n")
    fh:write("max_clients=", opts.maxconn, "\n\n")
  else
    fh:write("# Unlimited number of concurrent connections allowed\n")
    fh:write("max_clients=0\n\n")
  end

  if opts.maxipconn and opts.maxipconn > 0 then
    fh:write("# Limit maximum number of concurrent connections per IP\n")
    fh:write("max_per_ip=", opts.maxipconn, "\n\n")
  else
    fh:write("# Unlimited number of concurrent connections per IP allowed\n")
    fh:write("max_per_ip=0\n\n")
  end

  if opts.pasvfrom and opts.pasvto then
    fh:write("# Limit PASV port range\n")
    fh:write("pasv_min_port=", opts.pasvfrom, "\n")
    fh:write("pasv_max_port=", opts.pasvto, "\n\n")
  end

  -- some distribution-specific settings:
  if LC.distribution.family == "Debian" then
    fh:write("secure_chroot_dir=/var/run/vsftpd/empty\n\n")
  end

  if v_major >= 3 then
    -- allow writable root directory for chroot() (restricted in vsftpd since v2.3.5, but this
    -- configuration option is only available since 3.0.0 and still mostly undocumented :(
    fh:write("allow_writeable_chroot=YES\n")
  end

  if opts.ssl then
    fh:write("# enable TLS\n")
    fh:write("ssl_enable=YES\n")
    fh:write("allow_anon_ssl=YES\n")
    if opts.sslonly then
      fh:write("force_local_logins_ssl=YES\n")
      fh:write("force_local_data_ssl=YES\n")
    else
      fh:write("force_local_logins_ssl=NO\n")
      fh:write("force_local_data_ssl=NO\n")
    end
    fh:write("ssl_tlsv1=YES\n")
    fh:write("ssl_sslv2=NO\n")
    fh:write("ssl_sslv3=NO\n")
    fh:write("ssl_ciphers=", LC.liveconfig.DEFAULT_SSL_CIPHERS, "\n")
    fh:write("rsa_cert_file=", crtfile, "\n")
    fh:write("rsa_private_key_file=", keyfile, "\n")

    if v_major > 2 or (v_major == 2 and v_minor >= 1) then
      if opts.sslreuse == true then
        fh:write("require_ssl_reuse=YES\n")
      elseif opts.sslreuse == false then
        fh:write("require_ssl_reuse=NO\n")
      end
    end

  end

  LC.liveconfig.writeFooter(fh)
  fh:close()

  -- enable configuration
  LC.fs.rename(configfile .. ".tmp", configfile)

  -- check if password file for virtual users exists; if not, then create empty file to prevent error messages from PAM:
  if not LC.fs.is_file(passwdfile) then
    local dbload = find_dbload()
    if dbload == nil then return false, "db_load utility not found" end
    os.execute("printf \"\" | " .. dbload .. " -t hash -T " .. passwdfile)
    -- adjust permissions
    LC.fs.setperm(passwdfile, "0600", "root", "root")
  end

  -- update status file
  LC.liveconfig.writeStatus(statusfile, "vsftpd", opts.revision, os.date("%Y-%m-%d %H:%M:%S %Z"))

  return true
end

-- ---------------------------------------------------------------------------
local function addSysUser(user, group, home, shell)
--  LC.log.print(LC.log.INFO, "vsftpd.addSysUser() called")
  local fhw, msg
  local configfile  = LCS.vsftpd.config["configpath"] .. "/users/" .. user

  -- create user config file
  fhw, msg = io.open(configfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", configfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. configfile.. ".tmp' for writing: " .. msg
  end
  -- adjust owner & permissions - only vsftpd needs to read this file:
  LC.fs.setperm(configfile .. ".tmp", "0640", "root", "root")
  fhw:write("# Created by LiveConfig - DO NOT MODIFY\n");
  fhw:write("local_root=" .. home .. "\n")
  fhw:write("guest_username=" .. user .. "\n")
  fhw:close()
  LC.fs.rename(configfile .. ".tmp", configfile)

end

-- ---------------------------------------------------------------------------
local function delSysUser(user)
--  LC.log.print(LC.log.INFO, "vsftpd.delSysUser() called")
  local configfile  = LCS.vsftpd.config["configpath"] .. "/users/" .. user

  -- remove user config file
  os.remove(configfile)

end

-- ---------------------------------------------------------------------------
local function register_hooks()
  if LCS.vsftpd and LCS.vsftpd.managed then
    -- register callbacks only if this service is managed by LiveConfig
    LC.hooks.add("LC.users.addUser", addSysUser)
    LC.hooks.add("LC.users.delUser", delSysUser)
  end
end

-- ---------------------------------------------------------------------------
-- init()
--
-- Initialize module (if in use)
-- ---------------------------------------------------------------------------
function init()
--  LC.log.print(LC.log.INFO, "vsftpd.init() called")
  -- this service is managed by LiveConfig
  LCS.vsftpd.managed = true

  -- mark hook list as "dirty"
  LC.hooks.update()
end

-- ---------------------------------------------------------------------------
-- add(cfg, opts)
--
-- Add virtual FTP account
-- ---------------------------------------------------------------------------
function add(cfg, opts)
  LC.log.print(LC.log.INFO, "Adding/Updating virtual FTP account '", opts.name, "' (vsftpd)")

  local fhw, msg
  local configfile  = cfg["configpath"] .. "/users/" .. opts.name
  local passwdfile  = cfg["configpath"] .. "/passwd.db"

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configfile = opts.prefix .. configfile
    passwdfile = opts.prefix .. passwdfile
  end

  -- create user config file
  fhw, msg = io.open(configfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", configfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. configfile.. ".tmp' for writing: " .. msg
  end
  -- adjust owner & permissions - only vsftpd needs to read this file:
  LC.fs.setperm(configfile .. ".tmp", "0640", "root", "root")
  fhw:write("# Created by LiveConfig - DO NOT MODIFY\n");
  fhw:write("local_root=" .. opts.path .. "\n")
  fhw:write("guest_username=" .. opts.user .. "\n")
  fhw:close()
  LC.fs.rename(configfile .. ".tmp", configfile)

  local pwd = opts.password
  if string.sub(pwd, 1, 3) ~= "$1$" or string.len(pwd) ~= 34 then
    -- encrypt password
    pwd = LC.crypt.crypt(pwd)
  end

  -- add entry to password database
  -- Example: echo -e "virt1\nSALwWlL5CAfNE" | db_load -t hash -T users.db
  local dbload = find_dbload()
  if dbload == nil then return false, "db_load utility not found" end
  os.execute("printf \"" .. opts.name .. "\\n" .. pwd .. "\\n\" | " .. dbload .. " -t hash -T " .. passwdfile)
  -- adjust permissions
  LC.fs.setperm(passwdfile, "0600", "root", "root")

  return true
end

-- ---------------------------------------------------------------------------
-- del(cfg, opts)
--
-- Delete virtual FTP account
-- ---------------------------------------------------------------------------
function del(cfg, opts)
  LC.log.print(LC.log.INFO, "Deleting virtual FTP account (vsftpd)")

  local configfile  = cfg["configpath"] .. "/users/" .. opts.name
  local passwdfile  = cfg["configpath"] .. "/passwd.db"

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configfile = opts.prefix .. configfile
    passwdfile = opts.prefix .. passwdfile
  end

  -- remove entry from password database
  -- Because deleting of a record is not possible, we set the password to an
  -- empty value.
  -- Example: echo -e "virt1\n" | db_load -t hash -T users.db
  local dbload = find_dbload()
  if dbload == nil then return false, "db_load utility not found" end
  os.execute("printf \"" .. opts.name .. "\\n\\n\" | " .. dbload .. " -t hash -T " .. passwdfile)
  -- adjust permissions
  LC.fs.setperm(passwdfile, "0600", "root", "root")

  -- remove user config file
  os.remove(configfile)

  return true
end

-- ---------------------------------------------------------------------------
-- lock(cfg, users)
--
-- Lock virtual FTP user accounts
-- ---------------------------------------------------------------------------
function lock(cfg, users)
  LC.log.print(LC.log.INFO, "Locking virtual FTP accounts (vsftpd)")
  local fhw, msg, user

  local usersfile   = "/etc/ftpusers"
  if LC.fs.is_file("/etc/vsftpd/ftpusers") then
    usersfile = "/etc/vsftpd/ftpusers"
  end

  fhw, msg = io.open(usersfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", usersfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. usersfile.. ".tmp' for writing: " .. msg
  end
  -- adjust owner & permissions:
  LC.fs.setperm(usersfile .. ".tmp", "0644", "root", "root")

  if LC.fs.is_file(usersfile) then
    -- open existing ftpusers file
    local line, fhr
    fhr, msg = io.open(usersfile, "r")
    if fhr == nil then
      fhw:close()
      LC.log.print(LC.log.ERR, "Can't open '", usersfile, "' for reading: ", msg)
      return false, "Can't open '" .. usersfile.. "' for reading: " .. msg
    end

    while true do
      line = fhr:read()
      if line == nil then break end
      user = string.match(line, "^([%w_.-]+)")
      -- write this line only if user is not in our "lock" table (these are handled later)
      if user == nil or not LC.liveconfig.inTable(user, users) then
        fhw:write(line, "\n")
      end
    end
    fhr:close()
  end

  local i
  for i in pairs(users) do
    fhw:write(users[i], "\n")
  end

  fhw:close()
  LC.fs.rename(usersfile .. ".tmp", usersfile)

  return true
end

-- ---------------------------------------------------------------------------
-- unlock(cfg, users)
--
-- Unlock virtual FTP user accounts
-- ---------------------------------------------------------------------------
function unlock(cfg, users)
  LC.log.print(LC.log.INFO, "Unlocking virtual FTP accounts (vsftpd)")
  local fhw, msg, user

  local usersfile   = "/etc/ftpusers"
  if LC.fs.is_file("/etc/vsftpd/ftpusers") then
    usersfile = "/etc/vsftpd/ftpusers"
  end

  fhw, msg = io.open(usersfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", usersfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. usersfile.. ".tmp' for writing: " .. msg
  end
  -- adjust owner & permissions:
  LC.fs.setperm(usersfile .. ".tmp", "0644", "root", "root")

  if LC.fs.is_file(usersfile) then
    -- open existing ftpusers file
    local line, fhr
    fhr, msg = io.open(usersfile, "r")
    if fhr == nil then
      fhw:close()
      LC.log.print(LC.log.ERR, "Can't open '", usersfile, "' for reading: ", msg)
      return false, "Can't open '" .. usersfile.. "' for reading: " .. msg
    end

    while true do
      line = fhr:read()
      if line == nil then break end
      user = string.match(line, "^([%w_.-]+)")
      -- write this line only if user is not in our "unlock" table (so they get removed)
      if user == nil or not LC.liveconfig.inTable(user, users) then
        fhw:write(line, "\n")
      end
    end
    fhr:close()
  end

  fhw:close()
  LC.fs.rename(usersfile .. ".tmp", usersfile)

  return true
end

-- ---------------------------------------------------------------------------

-- register hooks
if LC.hooks then
  LC.hooks.register(register_hooks)
end

-- <EOF>----------------------------------------------------------------------
