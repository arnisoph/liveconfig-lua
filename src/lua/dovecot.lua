--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2013 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/dovecot.lua
-- Lua module to manage dovecot POP3/IMAP server
-- $Id: dovecot.lua 2849 2014-04-24 17:05:03Z kk $
-- ---------------------------------------------------------------------------
-- This is the "driver" module for dovecot pop/imap server.
-- It must be loaded by the command
--   LC.popimap.load("dovecot")
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
local ipairs = ipairs
local tonumber = tonumber

-- Module declaration
module("dovecot")

-- Exported functions
--   detect()
--   install()
--   uninstall()
--   configure()
--   addMailbox()
--   editMailbox()
--   deleteMailbox()

-- optionally disallow authentication via CRAM-MD5
-- (This is *ONLY* required if you have imported hashed password with
-- MD5-CRYPT scheme! Enable this option using your "custom.lua" only if you
-- really know what you're doing!
if DISABLE_CRAM == nil then
  DISABLE_CRAM = false
end

-- ---------------------------------------------------------------------------
-- getBinaryVersion()
--
-- Return the binary version number from dovecot
-- ---------------------------------------------------------------------------
local function getBinaryVersion(bin)
  local handle = io.popen(bin .. " --version", "r")
  local ret = handle:read("*a")
  handle:close()
  local v = string.match(ret, "(%d+%.%d+[%.%d+]*)")
  return v
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect if an dovecote pop/imap server is installed. If yes, return a table containing
-- all relevant informations:
--   type          => "dovecot"
--   binname       => file name of the dovecot binary (eg. "/usr/sbin/dovecot")
--   binversion    => binary version (eg. "2.5.5")
--   pkgname       => name of the package (see below)
--   pkgversion    => package version number (eg. "2.2.3-4+etch11")
--   configpath    => Main configuration path for dovecot
--   configfile    => LiveConfigs' configuration file (snippet)
--   statusfile    => LiveConfigs' status file (containing config version etc.)
--   defaultlog    => Default log file (for default and unknown/unconfigured vhosts)
--   start_cmd     => command to start dovecot
--   stop_cmd      => command to stop dovecot
--   reload_cmd    => command to re-load configuration
--   restart_cmd   => command to re-start dovecot process
--
-- If pkgversion is 'nil', then dovecot Server was most propably not installed
-- as native distribution package, but compiled/installed manually.
-- ---------------------------------------------------------------------------
function detect()

  local pkg, v, bin

  -- first check for distribution-specific packages
  if LC.distribution.family == "Debian" or LC.distribution.family == "Gentoo" or LC.distribution.family == "RedHat" or LC.distribution.family == "BSD" or LC.distribution.family == "SUSE" then
    -- Debian/Ubuntu Paketsearch
    if LC.distribution.family == "Debian" then
    -- Debian (all releases)
      pkg, v = LC.distribution.hasPackage('dovecot-common', 'dovecot-pop3d', 'dovecot-imapd')
    elseif LC.distribution.family == "SUSE" then
        -- OpenSUSE: check for both Dovecot 1.2 or 2.0:
        pkg, v = LC.distribution.hasPackage('dovecot21', 'dovecot20', 'dovecot12', 'dovecot')
    else
        -- Gentoo, CentOS
        pkg, v = LC.distribution.hasPackage('dovecot')
    end
    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      if LC.distribution.family == "BSD" then
        bin = "/usr/local/sbin/dovecot"
      else
        bin = "/usr/sbin/dovecot"
      end
      -- get binary version
      local bv = getBinaryVersion(bin)
      if bv ~= nil then
        -- ok, we have all informations. return data table:
        if LC.distribution.family == "RedHat" then
          local data = {
              ["type"]          = "dovecot",
              ["binname"]       = bin,
              ["binversion"]    = bv,
              ["pkgname"]       = pkg,
              ["pkgversion"]    = v,
              ["configpath"]    = "/etc/dovecot",
              ["configfile"]    = "/etc/dovecot.conf",
              ["userfile"]      = "/etc/dovecot/passwd",
              ["statusfile"]    = "/etc/dovecot/liveconfig.status",
              ["defaultlog"]    = "/var/log/maillog",
              ["start_cmd"]     = "/sbin/service dovecot start",
              ["stop_cmd"]      = "/sbin/service dovecot stop",
              ["reload_cmd"]    = "/sbin/service dovecot reload",
              ["restart_cmd"]   = "/sbin/service dovecot restart",
            }
          if string.match(bv, "^(%d+)") == "2" then
            -- Dovecot 2.x configuration
            data.configfile = "/etc/dovecot/dovecot.conf"
          end
          return data
        elseif LC.distribution.family == "BSD" then
            local data = {
                ["type"]          = "dovecot",
                ["binname"]       = bin,
                ["binversion"]    = bv,
                ["pkgname"]       = pkg,
                ["pkgversion"]    = v,
                -- Baustelle
                ["configpath"]    = "/etc/dovecot",
                ["configfile"]    = "/etc/dovecot/dovecot.conf",
                ["userfile"]      = "/etc/dovecot/passwd",
                ["statusfile"]    = "/etc/dovecot/liveconfig.status",
                ["defaultlog"]    = "/var/log/mail.log",
                ["start_cmd"]     = "/usr/local/etc/rc.d/dovecot start",
                ["stop_cmd"]      = "/usr/local/etc/rc.d/dovecot stop",
                ["reload_cmd"]    = "/usr/local/etc/rc.d/dovecot reload",
                ["restart_cmd"]   = "/usr/local/etc/rc.d/dovecot restart",
              }
            return data
        else
          local data = {
              ["type"]          = "dovecot",
              ["binname"]       = bin,
              ["binversion"]    = bv,
              ["pkgname"]       = pkg,
              ["pkgversion"]    = v,
              ["configpath"]    = "/etc/dovecot",
              ["configfile"]    = "/etc/dovecot/dovecot.conf",
              ["userfile"]      = "/etc/dovecot/passwd",
              ["statusfile"]    = "/etc/dovecot/liveconfig.status",
              ["defaultlog"]    = "/var/log/mail.log",
            }
          if LC.fs.is_file("/etc/init.d/dovecot") then
            data["start_cmd"]   = "/etc/init.d/dovecot start"
            data["stop_cmd"]    = "/etc/init.d/dovecot stop"
            data["reload_cmd"]  = "/etc/init.d/dovecot reload"
            data["restart_cmd"] = "/etc/init.d/dovecot restart"
          else
            data["start_cmd"]   = "/usr/sbin/service dovecot start"
            data["stop_cmd"]    = "/usr/sbin/service dovecot stop"
            data["reload_cmd"]  = "/usr/sbin/service dovecot reload"
            data["restart_cmd"] = "/usr/sbin/service dovecot restart"
          end
          if LC.distribution.family == "SUSE" then
            -- "restart" is quite broken at least in OpenSUSE 12.1, so do it manually:
            data["restart_cmd"] = "/bin/systemctl stop dovecot.service; /bin/systemctl kill dovecot.service; sleep 2; /bin/systemctl start dovecot.service"
          end
          return data
        end
      end
      -- else: fall trough, to check for custom dovecot installation
      LC.log.print(LC.log.DEBUG, "LC.dovecot.detect(): Found Dovecot package '", pkg, "', but no binary at ", bin)
    end
  end
end

-- ---------------------------------------------------------------------------
-- install(cfg, opts)
--
-- Install LiveConfig configuration files for Dovecot server
-- ---------------------------------------------------------------------------
function install(cfg, opts)
  LC.log.print(LC.log.INFO, "Activating management of Dovecot server")

  local fh, status, msg
  local configpath  = cfg["configpath"]
  local configfile  = cfg["configfile"]
  local statusfile  = cfg["statusfile"]
  local userfile    = cfg["userfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    statusfile = opts.prefix .. statusfile
    userfile   = opts.prefix .. userfile
  end

  -- for CentOS5 does not exists configpath...create
  if not LC.fs.is_dir(configpath) then
    LC.fs.mkdir(configpath)
  end
  -- back up old default configfile (if existing)
  if LC.fs.is_file(configfile) and not LC.fs.is_file( configfile .. ".lcbak") then
    LC.fs.rename( configfile,  configfile .. ".lcbak")
  end

  -- back up old default userfile file (if existing)
  if LC.fs.is_file(userfile) and not LC.fs.is_file( userfile .. ".lcbak") then
    LC.fs.rename( userfile,  userfile .. ".lcbak")
  end

  -- check whether mail user and group exists or not
  -- if not create user and group
  if not LC.sys.user_exists("mail") then
    if not LC.sys.group_exists("mail") then
      LC.users.addGroup("mail")
    end
    LC.users.addUser("mail", "mail", "/var/mail", "nologin")
  end

  -- create (empty) passwd file (if not existing)
  if not LC.fs.is_file(userfile) then
    local fh, msg = io.open(userfile, "a")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", userfile, "' for writing: ", msg)
      return false, "Can't open '" .. userfile .. "' for writing: " .. msg
    end
    -- adjust owner & permissions - only Dovecot needs access to this file, so set mod 600 !!!
    LC.fs.setperm(userfile, "0600", "dovecot", "root")
    fh:close()
  end

  -- write default config file dovecot.conf:
  configure(cfg, opts)

  -- create userfile (/etc/dovecot/passwd)
  os.execute("touch " .. userfile)
  -- adjust permissions
  LC.fs.setperm(userfile, "0600", "dovecot", "root")

  return true
end

-- ---------------------------------------------------------------------------
-- uninstall(cfg, opts)
--
-- Remove LiveConfig configuration files from Dovecot server
-- ---------------------------------------------------------------------------
function uninstall(cfg, opts)
  LC.log.print(LC.log.INFO, "Disabling management of Dovecot server")

  local status, msg
  local configpath = cfg["configpath"]
  local configfile = cfg["configfile"]
  local statusfile = cfg["statusfile"]
  local userfile   = cfg["userfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    statusfile = opts.prefix .. statusfile
    userfile   = opts.prefix .. userfile
  end

  -- restore original "dovecot.conf" (if existing...)
  if LC.fs.is_file( configfile .. ".lcbak") then
    LC.fs.rename( configfile .. ".lcbak", configfile)
  end
  -- restore original "/etc/dovecot/passwd" (if existing...)
  if LC.fs.is_file( userfile .. ".lcbak") then
    LC.fs.rename( userfile .. ".lcbak", userfile)
  end
  
  -- Currently do not delete (because dependencies with postfix)
  -- Delete user and group vmail
  -- local data  = { }
  -- data.user   = "vmail"
  -- data.group  = "vmail"
  -- data.home   = "vmail"
  -- data.shell  = "nologin"
  -- data.passwd = ""
  -- local uid = LC.sys.user_exists("vmail")
  -- if uid ~= false then 
  --   LC.users.delUser(data)
  -- end
  -- local gid = LC.sys.group_exists("vmail")
  -- if gid ~= false then
  --   LC.users.delGroup(data)
  -- end

  -- remove status file
  if LC.fs.is_file(statusfile) then
    os.remove(statusfile)
  end

  -- restart dovecot
  os.execute(cfg["restart_cmd"])

  return true
end


-- ---------------------------------------------------------------------------
-- configure(cfg, opts)
--
-- Configure dovecot Server
-- ---------------------------------------------------------------------------
function configure(cfg, opts)

  local fh, status, msg
  local statusfile = cfg["statusfile"]
  local configpath  = cfg["configpath"]
  local configfile  = cfg["configfile"]
  local v_major, v_minor = string.match(cfg.binversion, "^(%d+)%.(%d+)")
  v_major = tonumber(v_major)
  v_minor = tonumber(v_minor)

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    statusfile  = opts.prefix .. statusfile
    configfile  = opts.prefix .. configfile
    configpath  = opts.prefix .. configpath
  end

  fh, msg = io.open(configfile .. ".tmp", "w")
  if fh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", configfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. configfile.. ".tmp' for writing: " .. msg
  end
  -- adjust owner & permissions - both Postfix and Dovecot need access to this file, so set mod 644 !!!
  LC.fs.setperm(configfile .. ".tmp", "0644", "dovecot", "root")

  -- get uid and gid for user "mail"
  local uid = LC.sys.user_exists("mail")
  if uid == false then
    return false, "System user 'mail' does not exist, please create user"
  end
  local gid = LC.sys.group_exists("mail")
  if gid == false then
    return false, "System group 'mail' does not exist, please create group"
  end

  -- create/update SSL certificate file:
  local crtfile, keyfile
  if opts.ssl then
    local sfh
    crtfile = cfg.configpath .. "/ssl-cert.pem"
    keyfile = cfg.configpath .. "/ssl-key.pem"
    if LC.distribution.family == "Debian" then
      crtfile = "/etc/ssl/certs/dovecot.crt"
      keyfile = "/etc/ssl/private/dovecot.key"
    elseif LC.distribution.family == "RedHat" then
      crtfile = "/etc/pki/tls/certs/dovecot.crt"
      keyfile = "/etc/pki/tls/private/dovecot.key"
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

  -- create /etc/dovecot.conf  
  LC.liveconfig.writeHeader(fh)

  -- check version
  if v_major == 1 then
    -- Dovcot version 1.x

    LC.log.print(LC.log.DEBUG, "Dovecot version 1.x")

    if opts.ssl then
      if opts.sslports then
        fh:write("protocols = imap imaps pop3 pop3s\n")
      else
        fh:write("protocols = imap pop3\n")
      end
      if v_minor < 2 then
        fh:write("ssl_disable = no\n")
      else
        if opts.sslonly then
          fh:write("ssl = required\n")
        else
          fh:write("ssl = yes\n")
        end
      end
      if opts.sslpci then
        -- PCI compliant ciphers (actually, defending BEAST is not necessary on POP3/IMAP, but most dumb PCI scans don't care :(
        fh:write("ssl_cipher_list = ", LC.liveconfig.DEFAULT_SSL_PCI_CIPHERS, "\n")
      else
        fh:write("ssl_cipher_list = ", LC.liveconfig.DEFAULT_SSL_CIPHERS, "\n")
      end
      fh:write("ssl_cert_file = ", crtfile, "\n")
      fh:write("ssl_key_file = ", keyfile, "\n")
    else
      fh:write("protocols = imap pop3\n")
    end

    fh:write([[

login_greeting = server ready
disable_plaintext_auth = no
#log_path = /var/log/dovecot
log_timestamp = "%Y-%m-%d %H:%M:%S "
mail_privileged_group = mail
first_valid_uid = ]], uid, "\n", [[
protocol imap {
  mail_plugins = quota imap_quota
]])

    if opts.imapconn and v_minor > 0 then
      -- only available since v1.1 - bad for CentOS 5.x shipping with Dovecot 1.0.7 :(
      fh:write("  mail_max_userip_connections = ", opts.imapconn, "\n")
    end

    fh:write([[
}
protocol pop3 {
  pop3_uidl_format = %08Xu%08Xv
  mail_plugins = quota
]])

    if opts.pop3conn and v_minor > 0 then
      -- only available since v1.1 - bad for CentOS 5.x shipping with Dovecot 1.0.7 :(
      fh:write("  mail_max_userip_connections = ", opts.pop3conn, "\n")
    end

    fh:write([[
}
protocol lda {
  postmaster_address = postmaster@localhost
  hostname = localhost
  mail_plugins = quota sieve
  mail_plugin_dir = /usr/lib/dovecot/modules/lda
  auth_socket_path = /var/run/dovecot/auth-master
}
auth default {
]])

    -- optionally disable CRAM-MD5 authentication (see top of this file)
    if DISABLE_CRAM then
      fh:write("  mechanisms = plain login\n")
    else
      fh:write("  mechanisms = plain login cram-md5\n")
    end

    fh:write([[
  passdb passwd-file {
    args = /etc/dovecot/passwd
  }
  userdb passwd-file {
    args = /etc/dovecot/passwd
  }
  socket listen {
    client {
      path = /var/spool/postfix/private/auth
      mode = 0660
      user = postfix
      group = mail
    }
    master {
      path = /var/run/dovecot/auth-master
      mode = 0600
      user = mail
      group = mail
    }
  }
  user = root
}
plugin {
  quota = maildir:User quota
  quota_rule = *:storage=0
  quota_rule2 = Trash:storage=50M
]])
    if opts.quotawarning then
      fh:write("  quota_warning = storage=95%% /usr/lib/liveconfig/mailquota.sh 95\n")
      fh:write("  quota_warning2 = storage=80%% /usr/lib/liveconfig/mailquota.sh 80\n")
    end
    fh:write([[
}
]])

  else
    -- Dovecot version 2.x
    LC.log.print(LC.log.DEBUG, "Dovcot version 2.x")

    fh:write([[

login_greeting = server ready
]])
    -- optionally disable CRAM-MD5 authentication (see top of this file)
    if DISABLE_CRAM then
      fh:write("auth_mechanisms = plain login\n")
    else
      fh:write("auth_mechanisms = plain login cram-md5\n")
    end
    fh:write([[
disable_plaintext_auth = no
ssl = no
first_valid_uid = ]], uid, "\n", [[
postmaster_address = postmaster@localhost
log_timestamp = "%Y-%m-%d %H:%M:%S "
mail_privileged_group = mail
mail_plugins = $mail_plugins quota
passdb {
  args = /etc/dovecot/passwd
  driver = passwd-file
}
plugin {
  quota = maildir:User quota
  quota_rule = *:storage=0
  quota_rule2 = Trash:storage=+50M
}
]])
    if opts.quotawarning then
      fh:write([[
plugin {
  quota_warning = storage=95%% quota-warning 95 %u
  quota_warning2 = storage=80%% quota-warning 80 %u
}
service quota-warning {
  executable = script /usr/lib/liveconfig/mailquota.sh
  user = mail
  unix_listener quota-warning {
    user = mail
    group = mail
    mode = 0600
  }
}
]])

    end

    fh:write([[

protocols = imap pop3
protocol imap {
  mail_plugins = $mail_plugins imap_quota
]])
    if opts.imapconn then
      fh:write("  mail_max_userip_connections = ", opts.imapconn, "\n")
    end
    fh:write([[
}
protocol pop3 {
  pop3_client_workarounds = outlook-no-nuls oe-ns-eoh
]])
    if opts.pop3conn then
      fh:write("  mail_max_userip_connections = ", opts.pop3conn, "\n")
    end
    fh:write([[
}
protocol lda {
  mail_plugins = $mail_plugins sieve
}
]])

    if opts.ssl then
      if opts.sslonly then
        fh:write("ssl = required\n")
      else
        fh:write("ssl = yes\n")
      end
      if opts.sslpci then
        -- PCI compliant ciphers (actually, defending BEAST is not necessary on POP3/IMAP, but most dumb PCI scans don't care :(
        fh:write("ssl_cipher_list = ", LC.liveconfig.DEFAULT_SSL_PCI_CIPHERS, "\n")
      else
        fh:write("ssl_cipher_list = ", LC.liveconfig.DEFAULT_SSL_CIPHERS, "\n")
      end
      fh:write("ssl_cert = <", crtfile, "\n")
      fh:write("ssl_key = <", keyfile, "\n")

      if not opts.sslports then
    fh:write([[
service imap-login {
  inet_listener imaps {
    port = 0
  }
}
service pop3-login {
  inet_listener pop3s {
    port = 0
  }
}
]])
      end
    end

    fh:write([[
service auth {
  unix_listener auth-userdb {
    group = mail
    mode = 0600
    user = mail
  }
  unix_listener /var/spool/postfix/private/auth {
    group = mail
    mode = 0660
    user = postfix
  }
  unix_listener auth-master {
    group = mail
    mode = 0600
    user = mail
  }
  user = root
}
userdb {
  args = /etc/dovecot/passwd
  driver = passwd-file
}

]])

  end

  LC.liveconfig.writeFooter(fh)
  fh:close()

  if v_major == 1 then
    -- Dovcot version 1.x
    if opts.quotawarning then
      -- create copy of config file, remove quota warnings to avoid loops:
      os.execute("sed -e 's/^[ \t]*quota_warning[0-9]*[ \t]*=.*$//' " .. configfile .. " >" .. configfile .. ".noquota")
      LC.fs.setperm(configfile .. ".noquota", "0644", "dovecot", "root")
    elseif LC.fs.is_file(configfile .. ".noquota") then
      -- remove old "noquota" config file
      os.execute("rm " .. configfile .. ".noquota")
    end
  end

  -- enable configuration
  LC.fs.rename(configfile .. ".tmp", configfile)

  -- update status file
  LC.liveconfig.writeStatus(statusfile, "dovecot", opts.revision, os.date("%Y-%m-%d %H:%M:%S %Z"))

  return true
end

-- ---------------------------------------------------------------------------
-- addMailbox
--
-- Add a mailbox to dovecot server
-- ---------------------------------------------------------------------------
function addMailbox(cfg, opts, data)

  local userfile  = cfg["userfile"]
  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    userfile = opts.prefix .. userfile
  end

  LC.log.print(LC.log.INFO, "Adding/updating user account " .. data.name .. "@" .. data.domain .. " at dovecot config file: " .. userfile)

  -- get uid and gid for user "mail"
  local uid = LC.sys.user_exists("mail")
  if uid == false then
    return false, "System user 'mail' does not exist, please create user"
  end
  local gid = LC.sys.group_exists("mail")
  if gid == false then
    return false, "System group 'mail' does not exist, please create group"
  end

  -- check if contract directory already exists, otherwise create it:
  if not LC.fs.is_dir('/var/mail/' .. data.contract) then
    if LC.fs.is_file('/var/mail/' .. data.contract) then
      os.remove('/var/mail/' .. data.contract)
    end
    LC.fs.mkdir_rec('/var/mail/' .. data.contract)
    LC.fs.setperm('/var/mail/' .. data.contract, "2700", "mail", "mail")
  end

  -- check if mailbox directory already exists, otherwise create it:
  if not LC.fs.is_dir('/var/mail/' .. data.contract .. '/' .. data.id) then
    LC.fs.mkdir_rec('/var/mail/' .. data.contract .. '/' .. data.id)
    LC.fs.setperm('/var/mail/' .. data.contract .. '/' .. data.id, "2700", "mail", "mail")
  end

  -- add entry to user file
  local fhr, fhw, msg
  if not LC.fs.is_file(userfile) then
    fhr, msg = io.open(userfile, "a")
    if fhr == nil then
      LC.log.print(LC.log.ERR, "Can't open '", userfile, "' for appending: ", msg)
      return false, "Can't open '" .. userfile .. "' for appending: " .. msg
    end
    -- adjust owner & permissions - only Dovecot needs access to this file, so set mod 600 !!!
    LC.fs.setperm(userfile, "0600", "dovecot", "root")
    fhr:close()
  end

  fhr, msg = io.open(userfile, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", userfile, "' for reading: ", msg)
    return false, "Can't open '" .. userfile .. "' for reading: " .. msg
  end

  fhw, msg = io.open(userfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", userfile .. ".tmp", "' for writing: ", msg)
    fhr:close()
    return false, "Can't open '" .. userfile .. ".tmp" .. "' for writing: " .. msg
  end
  -- adjust owner & permissions - only Postfix needs to read this file:
  LC.fs.setperm(userfile .. ".tmp", "0600", "dovecot", "root")

  -- build new/updated entry:
  local new_line = nil
  if data.password ~= nil then
    local pwd, algo
    if string.len(data.password) == 34 and string.match(data.password, "^$1$%w%w%w%w%w%w%w%w$[%w./]+$") then
      -- MD5-CRYPT password (propably imported via SOAP interface)
      pwd = data.password
      algo = "MD5-CRYPT"
    else
      -- create CRAM-MD5 hash
      pwd = LC.crypt.cram_md5(data.password)
      algo = "CRAM-MD5"
    end
    new_line = data.name .. "@" .. data.domain .. ":{" .. algo .. "}" .. pwd .. ":" .. uid .. ":" .. gid .. "::/var/mail::userdb_mail=maildir:/var/mail/" .. data.contract .. "/" .. data.id .. "/"
    if data.quota ~= nil and data.quota > 0 then
      new_line = new_line .. " userdb_quota_rule=*:storage=" .. data.quota .. "MB"
    end
    new_line = new_line .. " userdb_sieve=/var/mail/" .. data.contract .. "/" .. data.id .. "/dovecot.sieve"
  end

  -- search/replace existing entry
  local search
  if data.old_addr == nil then
    search = "^" .. data.name .. "@" .. data.domain .. ":"
  else
    -- rename existing mailbox
    search = "^" .. data.old_addr .. ":"
  end
  search = string.gsub(search, "%%", "%%%%")
  search = string.gsub(search, "%.", "%%.")
  search = string.gsub(search, "%-", "%%-")
  local line
  local found = false
  while true do
    line = fhr:read()
    if line == nil then break end
    if string.find(line, search) ~= nil then
      found = true
      if new_line ~= nil then
        fhw:write(new_line, "\n")
      end
    else
      fhw:write(line, "\n")
    end
  end

  fhr:close()

  if found == false and new_line ~= nil then
    -- append new entry
    fhw:write(new_line, "\n")
  end

  fhw:close()

  -- move temporary file to new password file
  LC.fs.rename(userfile .. ".tmp", userfile)

  -- check for autoresponder
  local sievepath = "/var/mail/" .. data.contract .. "/" .. data.id
  if data.autoresponder == true then
    -- create autoresponder
    fhw, msg = io.open(sievepath .. "/dovecot.sieve.tmp", "w")
    if fhw == nil then
      LC.log.print(LC.log.ERR, "Can't open '", sievepath .. "/dovecot.sieve.tmp", "' for writing: ", msg)
      return false, "Can't open '" .. sievepath .. "/dovecot.sieve.tmp" .. "' for writing: " .. msg
    end
    -- adjust owner & permissions - only Dovecot (mail) needs to read this file:
    LC.fs.setperm(sievepath .. "/dovecot.sieve.tmp", "0640", "mail", "mail")
    -- escape quotes
    local as = string.gsub(data.autosubject, "\\", "\\\\")
    as = string.gsub(as, "\"", "\\\"")
    local am = string.gsub(data.automessage, "\\", "\\\\")
    am = string.gsub(am, "\"", "\\\"")
    fhw:write([[
# Created by LiveConfig
require ["vacation"];
vacation
  :days 1
]])
    fhw:write("  :subject \"", as, "\"\n")
    fhw:write("  :addresses [\"", data.name, "@", data.domain, "\"")
    if type(data.aliases) == "table" then
      local i,s
      for i, s in ipairs(data.aliases) do
        fhw:write(", \"", s, "@", data.domain, "\"")
      end
    end
    fhw:write("]\n")
    fhw:write("\"", am, "\";\n")
    fhw:close()
    LC.fs.rename(sievepath .. "/dovecot.sieve.tmp", sievepath .. "/dovecot.sieve")
  else
    -- delete autoresponder if still existing...
    if LC.fs.is_file(sievepath .. "/dovecot.sieve") then
      os.remove(sievepath .. "/dovecot.sieve")
      os.remove(sievepath .. "/dovecot.svbin")
    end
  end

  return true

end

-- ---------------------------------------------------------------------------
-- editMailbox
--
-- Edit mailbox configuration
-- ---------------------------------------------------------------------------
function editMailbox(cfg, opts, data)
  -- same as addMailbox():
  return addMailbox(cfg, opts, data)
end

-- ---------------------------------------------------------------------------
-- deleteMailbox
--
-- Delete a mailbox
-- ---------------------------------------------------------------------------
function deleteMailbox(cfg, opts, data)

  local userfile  = cfg["userfile"]
  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    userfile = opts.prefix .. userfile
  end

  LC.log.print(LC.log.INFO, "Deleting mailbox " .. data.name .. "@" .. data.domain .. " from dovecot config file: " .. userfile)

  -- remove entry from user file
  local fhr, fhw, msg
  if not LC.fs.is_file(userfile) then
    fhr, msg = io.open(userfile, "a")
    if fhr == nil then
      LC.log.print(LC.log.ERR, "Can't open '", userfile, "' for appending: ", msg)
      return false, "Can't open '" .. userfile .. "' for appending: " .. msg
    end
    -- adjust owner & permissions - only Dovecot needs access to this file, so set mod 600 !!!
    LC.fs.setperm(userfile, "0600", "dovecot", "root")
    fhr:close()
  end

  fhr, msg = io.open(userfile, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", userfile, "' for reading: ", msg)
    return false, "Can't open '" .. userfile .. "' for reading: " .. msg
  end

  fhw, msg = io.open(userfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", userfile .. ".tmp", "' for writing: ", msg)
    fhr:close()
    return false, "Can't open '" .. userfile .. ".tmp" .. "' for writing: " .. msg
  end
  -- adjust owner & permissions - only Postfix needs to read this file:
  LC.fs.setperm(userfile .. ".tmp", "0600", "dovecot", "root")

  -- search/remove existing entry
  local search = "^" .. data.name .. "@" .. data.domain .. ":"
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
    else
--      LC.log.print(LC.log.DEBUG, "  not found")
      fhw:write(line, "\n")
    end
  end

  fhr:close()

  fhw:close()

  -- move temporary file to new password file
  LC.fs.rename(userfile .. ".tmp", userfile)

  -- remove mailbox directory
  if data.id and LC.fs.is_dir("/var/mail/" .. data.contract .. "/" .. data.id) then
    os.execute("rm -rf /var/mail/" .. data.contract .. "/" .. data.id)
  end

  if LC.fs.is_dir("/var/mail/" .. data.contract) and LC.fs.filecount("/var/mail/" .. data.contract) == 0 then
    os.execute("rmdir /var/mail/" .. data.contract)
  end

  return true

end


-- <EOF>----------------------------------------------------------------------
