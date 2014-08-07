--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2014 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/postfix.lua
-- Lua module to manage postfix smtp server
-- $Id: postfix.lua 2914 2014-06-11 07:23:09Z kk $
-- ---------------------------------------------------------------------------
-- This is the "driver" module for postfix smtp server.
-- It must be loaded by the command
--   LC.smtp.load("postfix")
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
local pairs = pairs
local tonumber = tonumber

-- Module declaration
module("postfix")

-- Exported functions
--   detect()
--   install()
--   uninstall()
--   configure()
--   addMailbox()
--   editMailbox()
--   deleteMailbox()
--   update_lclogparse()

-- Optionally disable updating main.cf/master.cf by LiveConfig
if NOUPDATE == nil then
  NOUPDATE = false
end

-- ---------------------------------------------------------------------------
-- getBinaryVersion()
--
-- Return the binary version number from postfix
-- ---------------------------------------------------------------------------
local function getBinaryVersion(bin)
  local handle = io.popen(postconfpath .. "postconf -d|grep mail_version", "r")
  local ret = handle:read("*a")
  handle:close()
  local v = string.match(ret, "(%d+%.%d+[%.%d+]*)")
  return v
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect if an postfix smtp server is installed. If yes, return a table containing
-- all relevant informations:
--   type          => "postfix"
--   binname       => file name of the postfix binary (eg. "/usr/sbin/postfix")
--   binversion    => binary version (eg. "2.5.5")
--   pkgname       => name of the package (see below)
--   pkgversion    => package version number (eg. "2.2.3-4+etch11")
--   configpath    => Main configuration path for postfix
--   configfile    => LiveConfigs' configuration file (snippet)
--   statusfile    => LiveConfigs' status file (containing config version etc.)
--   defaultlog    => Default log file (for default and unknown/unconfigured vhosts)
--   start_cmd     => command to start postfix
--   stop_cmd      => command to stop postfix
--   reload_cmd    => command to re-load configuration
--   restart_cmd   => command to re-start postfix process
--
-- If pkgversion is 'nil', then Postfix Server was most propably not installed
-- as native distribution package, but compiled/installed manually.
-- ---------------------------------------------------------------------------
function detect()

  local bin
  -- first check for distribution-specific packages
  if LC.distribution.family == "Debian" or LC.distribution.family == "Gentoo" or LC.distribution.family == "RedHat" or LC.distribution.family == "BSD" or LC.distribution.family == "SUSE"  then
    -- Debian/Ubuntu and Gentoo
    local pkg, v = LC.distribution.hasPackage('postfix')
    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      if LC.distribution.family == "BSD" then
        postconfpath = "/usr/local/sbin/"
        bin = "/usr/local/sbin/postfix"
      else
        postconfpath = "/usr/sbin/"
        bin = "/usr/sbin/postfix"
      end
      -- get binary version
      local bv = getBinaryVersion(bin)
      if bv ~= nil then
        local data
        if LC.distribution.family == "RedHat" then
          data = {
            ["type"]          = "postfix",
            ["binname"]       = bin,
            ["binversion"]    = bv,
            ["pkgname"]       = pkg,
            ["pkgversion"]    = v,
            ["configpath"]    = "/etc/postfix",
            ["configfile"]    = "/etc/postfix/main.cf",
            ["statusfile"]    = "/etc/postfix/liveconfig.status",
            ["domainsfile"]   = "/etc/postfix/virtual_domains",
            ["aliasfile"]     = "/etc/postfix/virtual_alias",
            ["mailboxfile"]   = "/etc/postfix/virtual_mailbox",
            ["defaultlog"]    = "/var/log/maillog",
            ["start_cmd"]     = "/sbin/service postfix start",
            ["stop_cmd"]      = "/sbin/service postfix stop",
            ["reload_cmd"]    = "/sbin/service postfix reload",
            ["restart_cmd"]   = "/sbin/service postfix restart",
            ["logfile"]       = "/var/log/maillog",
            }
        elseif LC.distribution.family == "BSD" then
          data = {
            ["type"]          = "postfix",
            ["binname"]       = bin,
            ["binversion"]    = bv,
            ["pkgname"]       = pkg,
            ["pkgversion"]    = v,
            ["configpath"]    = "/usr/local/etc/postfix",
            ["configfile"]    = "/usr/local/etc/postfix/main.cf",
            ["statusfile"]    = "/usr/local/etc/postfix/liveconfig.status",
            ["domainsfile"]   = "/usr/local/etc/postfix/virtual_domains",
            ["aliasfile"]     = "/usr/local/etc/postfix/virtual_alias",
            ["mailboxfile"]   = "/usr/local/etc/postfix/virtual_mailbox",
            ["defaultlog"]    = "/var/log/maillog",
            ["start_cmd"]     = "/usr/local/etc/rc.d/postfix onestart",
            ["stop_cmd"]      = "/usr/local/etc/rc.d/postfix onestop",
            ["reload_cmd"]    = "/usr/local/etc/rc.d/postfix reload",
            ["restart_cmd"]   = "/usr/local/etc/rc.d/postfix onerestart",
            }
        else
          data = {
            ["type"]          = "postfix",
            ["binname"]       = bin,
            ["binversion"]    = bv,
            ["pkgname"]       = pkg,
            ["pkgversion"]    = v,
            ["configpath"]    = "/etc/postfix",
            ["configfile"]    = "/etc/postfix/main.cf",
            ["statusfile"]    = "/etc/postfix/liveconfig.status",
            ["domainsfile"]   = "/etc/postfix/virtual_domains",
            ["aliasfile"]     = "/etc/postfix/virtual_alias",
            ["mailboxfile"]   = "/etc/postfix/virtual_mailbox",
            ["defaultlog"]    = "/var/log/mail.log",
            ["start_cmd"]     = "/etc/init.d/postfix start",
            ["stop_cmd"]      = "/etc/init.d/postfix stop",
            ["reload_cmd"]    = "/etc/init.d/postfix reload",
            ["restart_cmd"]   = "/etc/init.d/postfix restart",
            ["logfile"]       = "/var/log/mail.log",
            }
          if LC.distribution.family == "SUSE" then
            data.logfile = "/var/log/mail"
          end
        end
        -- now check for clamav-milter:
        if LC.distribution.family == "Debian" then
          pkg, v = LC.distribution.hasPackage("clamav-milter")
          if pkg ~= nil then
            data["clamav"]    = v;
            data["clamav_milter_cfg"] = "/etc/clamav/clamav-milter.conf";
            data["clamav_milter_socket"] = "unix:/var/run/clamav/clamav-milter.ctl";
          end
        elseif LC.distribution.family == "RedHat" then
          pkg, v = LC.distribution.hasPackage("clamav-milter")
          if pkg ~= nil then
            data["clamav"]    = v;
            -- default settings (RedHat 5.x)
            data["clamav_milter_cfg"] = "/etc/clamav-milter.conf";
            data["clamav_milter_socket"] = "unix:/var/clamav/clmilter.socket";
            if LC.fs.is_file("/etc/clamav/clamav-milter.conf") then
              -- RedHat 6.x
              data["clamav_milter_cfg"] = "/etc/clamav/clamav-milter.conf";
              data["clamav_milter_socket"] = "unix:/var/run/clamav/clamav-milter.ctl";
            end
          end
        elseif LC.distribution.family == "SUSE" then
          pkg, v = LC.distribution.hasPackage("clamav")
          if pkg ~= nil and LC.fs.is_file("/usr/sbin/clamav-milter") then
            data["clamav"]    = v;
            data["clamav_milter_cfg"] = "/etc/clamav-milter.conf";
            data["clamav_milter_socket"] = "unix:/var/lib/clamav/clamav-milter-socket";
          end
        elseif LC.distribution.family == "Gentoo" then
          pkg, v = LC.distribution.hasPackage("clamav")
          if pkg ~= nil and LC.fs.is_file("/usr/sbin/clamav-milter") then
            data["clamav"]    = v;
            data["clamav_milter_cfg"] = "/etc/clamav-milter.conf";
            data["clamav_milter_socket"] = "unix:/var/run/clamav/clamav-milter.sock";
          end
        end
        -- now check for Postgrey:
        pkg, v = LC.distribution.hasPackage("postgrey")
        if pkg ~= nil then
          data["postgrey"] = v;
        end
        return data
      end
      -- else: fall trough, to check for custom postfix installation
      LC.log.print(LC.log.DEBUG, "LC.postfix.detect(): Found Postfix package '", pkg, "', but no binary at ", bin)
    end
  end
end
-- ---------------------------------------------------------------------------
-- install(cfg, opts)
--
-- Install LiveConfig configuration files for Postfix Server
-- ---------------------------------------------------------------------------
function install(cfg, opts)
  LC.log.print(LC.log.INFO, "Activating management of Postfix Server")

  local fh, status, msg
  local configpath  = cfg["configpath"]
  local configfile  = cfg["configfile"]
  local masterfile  = cfg["configpath"] .. "/master.cf"
  local statusfile  = cfg["statusfile"]
  local domainsfile = cfg["domainsfile"]
  local aliasfile   = cfg["aliasfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    masterfile = opts.prefix .. masterfile
    statusfile = opts.prefix .. statusfile
    domainsfile = opts.prefix .. domainsfile
    aliasfile   = opts.prefix .. aliasfile
  end

  -- back up old default main.cf file (if existing)
  if LC.fs.is_file(configfile) and not LC.fs.is_file(configfile .. ".lcbak") then
    LC.fs.rename(configfile, configfile .. ".lcbak")
  end
  -- back up old default master.cf file (if existing)
  if LC.fs.is_file(masterfile) and not LC.fs.is_file(masterfile .. ".lcbak") then
    LC.fs.rename(masterfile, masterfile .. ".lcbak")
  end
  -- back up old domainsfile (if existing)
  if LC.fs.is_file(domainsfile) and not LC.fs.is_file(domainsfile .. ".lcbak") then
    LC.fs.rename(domainsfile, domainsfile .. ".lcbak")
  end
  -- back up old domainsfile database file (if existing)
  if LC.fs.is_file(domainsfile .. ".db") and not LC.fs.is_file(domainsfile .. ".db.lcbak") then
    LC.fs.rename(domainsfile .. ".db", domainsfile .. ".db.lcbak")
  end
  -- back up old aliasfile (if existing)
  if LC.fs.is_file(aliasfile) and not LC.fs.is_file(aliasfile .. ".lcbak") then
    LC.fs.rename(aliasfile, aliasfile .. ".lcbak")
  end
  -- back up old aliasfile database file (if existing)
  if LC.fs.is_file(aliasfile .. ".db") and not LC.fs.is_file(aliasfile .. ".db.lcbak") then
    LC.fs.rename(aliasfile .. ".db", aliasfile .. ".db.lcbak")
  end

  -- check whether mail user and group exists or not
  -- if not create user and group
  if not LC.sys.user_exists("mail") then
    if not LC.sys.group_exists("mail") then
      LC.users.addGroup("mail")
    end
    LC.users.addUser("mail", "mail", "/var/mail", "nologin")
  end

  -- write default config file main.cf:
  configure(cfg, opts)

  -- create lclogparse.conf:
  update_lclogparse(cfg)

  return true
end

-- ---------------------------------------------------------------------------
-- uninstall(cfg, opts)
--
-- Remove LiveConfig configuration files from Postfix Server
-- ---------------------------------------------------------------------------
function uninstall(cfg, opts)
  LC.log.print(LC.log.INFO, "Disabling management of Postfix Server")

  local status, msg
  local configpath  = cfg["configpath"]
  local configfile  = cfg["configfile"]
  local masterfile  = cfg["configpath"] .. "/master.cf"
  local statusfile  = cfg["statusfile"]
  local domainsfile = cfg["domainsfile"]
  local aliasfile   = cfg["aliasfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath  = opts.prefix .. configpath
    configfile  = opts.prefix .. configfile
    masterfile  = opts.prefix .. masterfile
    statusfile  = opts.prefix .. statusfile
    domainsfile = opts.prefix .. domainsfile
    aliasfile   = opts.prefix .. aliasfile
  end
  local sender_access_file = cfg["configpath"] .. "/sender_access"
  local recipient_access_file = cfg["configpath"] .. "/recipient_access"
  local greylist_file = cfg["configpath"] .. "/greylist_addrs"

  -- restore original "main.cf" (if existing...)
  if LC.fs.is_file(configfile .. ".lcbak") then
    LC.fs.rename(configfile .. ".lcbak", configfile)
  end
  -- restore original "master.cf" (if existing...)
  if LC.fs.is_file(masterfile .. ".lcbak") then
    LC.fs.rename(masterfile .. ".lcbak", masterfile)
  end
  -- restore original domainsfile (if existing...)
  if LC.fs.is_file(domainsfile .. ".lcbak") then
    LC.fs.rename(domainsfile .. ".lcbak", domainsfile)
  end
  -- restore original domainsfile database (if existing...)
  if LC.fs.is_file(domainsfile .. ".db.lcbak") then
    LC.fs.rename(domainsfile .. ".db.lcbak", domainsfile .. ".db")
  end
  -- restore original aliasfile (if existing...)
  if LC.fs.is_file(aliasfile .. ".lcbak") then
    LC.fs.rename(aliasfile .. ".lcbak", aliasfile)
  end
  -- restore original aliasfile database (if existing...)
  if LC.fs.is_file(aliasfile .. ".db.lcbak") then
    LC.fs.rename(aliasfile .. ".db.lcbak", aliasfile .. ".db")
  end

  -- Currently do not delete (because dependencies with dovecot)
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

  -- remove sender_access file
  if LC.fs.is_file(sender_access_file) then
    os.remove(sender_access_file)
  end
  if LC.fs.is_file(sender_access_file .. ".db") then
    os.remove(sender_access_file .. ".db")
  end

  -- remove recipient_access file
  if LC.fs.is_file(recipient_access_file) then
    os.remove(recipient_access_file)
  end
  if LC.fs.is_file(recipient_access_file .. ".db") then
    os.remove(recipient_access_file .. ".db")
  end

  -- remove greylist_addrs file
  if LC.fs.is_file(greylist_file) then
    os.remove(greylist_file)
  end
  if LC.fs.is_file(greylist_file .. ".db") then
    os.remove(greylist_file .. ".db")
  end

  -- remove status file
  if LC.fs.is_file(statusfile) then
    os.remove(statusfile)
  end

  -- restart postfix
  os.execute(cfg["restart_cmd"])

  return true
end


-- ---------------------------------------------------------------------------
-- configure(cfg, opts)
--
-- Configure Postfix Server
-- ---------------------------------------------------------------------------
function configure(cfg, opts)

  local fh, status, msg
  local statusfile = cfg["statusfile"]
  local configpath = cfg["configpath"]
  local configfile = cfg["configfile"]
  local masterfile = cfg["configpath"] .. "/master.cf"
  local domainsfile = cfg["domainsfile"]
  local aliasfile   = cfg["aliasfile"]
  local v_major, v_minor = string.match(cfg.binversion, "^(%d+)%.(%d+)")
  v_major = tonumber(v_major)
  v_minor = tonumber(v_minor)

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    statusfile = opts.prefix .. statusfile
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    masterfile = opts.prefix .. masterfile
    domainsfile = opts.prefix .. domainsfile
    aliasfile   = opts.prefix .. aliasfile
  end
  local sender_access_file = cfg["configpath"] .. "/sender_access"
  local recipient_access_file = cfg["configpath"] .. "/recipient_access"
  local greylist_file = cfg["configpath"] .. "/greylist_addrs"

  -- get uid and gid for 'mail' user
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
      crtfile = "/etc/ssl/certs/postfix.crt"
      keyfile = "/etc/ssl/private/postfix.key"
    elseif LC.distribution.family == "RedHat" then
      crtfile = "/etc/pki/tls/certs/postfix.crt"
      keyfile = "/etc/pki/tls/private/postfix.key"
    end
    sfh, msg = io.open(crtfile, "w")
    LC.fs.setperm(crtfile, "0640", "root", "postfix")
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
    LC.fs.setperm(keyfile, "0640", "root", "postfix")
    if sfh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", keyfile, "' for writing: ", msg)
      return false, "Can't open '" .. keyfile .. "' for writing: " .. msg
    end
    sfh:write(opts.ssl_key)
    sfh:close()
  end

  if NOUPDATE then
    LC.log.print(LC.log.INFO, "Won't update Postfix configuration (postfix.NOUPDATE=true)")
  else
    -- create configuration file
    fh, msg = io.open(configfile .. ".tmp", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", configfile, ".tmp' for writing: ", msg)
      return false, "Can't open '" .. configfile.. ".tmp' for writing: " .. msg
    end
    -- adjust owner & permissions - only Postfix needs to read this file:
    LC.fs.setperm(configfile .. ".tmp", 644, "root", "postfix")

    LC.liveconfig.writeHeader(fh)

    fh:write([[
smtpd_banner = $myhostname ESMTP $mail_name
biff = no

append_dot_mydomain = no
readme_directory = no

# Inbound IP addresses
]])
    
    local ipv4count = 0
    local ipv6count = 0
    if type(opts.ips) == "table" then
      -- bound to specific IPs
      fh:write("inet_interfaces = ")
      local i, s
      for i, s in ipairs(opts.ips) do
        if ipv4count + ipv6count > 0 then fh:write(", ") end
        fh:write(s)
        if string.find(s, "%.") then
          ipv4count = ipv4count + 1
        else
          ipv6count = ipv6count + 1
        end
      end
      if ipv4count > 0 then
        fh:write(", 127.0.0.1")
      end
      if ipv6count > 0 then
        fh:write(", ::1")
      end
      fh:write("\n")
    elseif opts.ips == 0 then
      -- all protocols
      ipv4count = 1
      ipv6count = 1
    elseif opts.ips == 1 then
      -- all IPv4 interfaces
      ipv4count = 1
    elseif opts.ips == 2 then
      -- all IPv6 interfaces
      ipv6count = 1
    end

    if opts.out_ipv4 then
      ipv4count = 1
    end
    if opts.out_ipv6 and opts.out_ipv6 ~= "" then
      ipv6count = 1
    end

    if ipv4count > 0 and ipv6count == 0 then
      fh:write("inet_protocols = ipv4\n")
    elseif ipv4count == 0 and ipv6count > 0 then
      fh:write("inet_protocols = ipv6\n")
    else
      fh:write("inet_protocols = all\n")
    end

    fh:write([[
# TLS parameters
smtp_tls_security_level = may
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
]])

    if (LC.distribution.family == "Debian" or LC.distribution.family == "Gentoo") and LC.fs.is_file("/etc/ssl/certs/ca-certificates.crt") then
      fh:write("smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt\n")
    elseif LC.distribution.family == "SUSE" and LC.fs.is_file("/etc/ssl/ca-bundle.pem") then
      fh:write("smtp_tls_CAfile = /etc/ssl/ca-bundle.pem\n")
    elseif LC.distribution.family == "RedHat" and LC.fs.is_file("/etc/pki/tls/certs/ca-bundle.crt") then
      fh:write("smtp_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt\n")
    end

    if opts.ssl then
      if LC.bits.band(opts.sslmode, 4) > 0 then
        -- force encrypted connections for user authentication
        fh:write("smtpd_tls_auth_only = yes\n")
      end
      fh:write([[
smtpd_tls_security_level = may
smtpd_tls_cert_file = ]], crtfile, "\n", [[
smtpd_tls_key_file = ]], keyfile, "\n", [[
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
]])
      if (LC.distribution.family == "Debian" or LC.distribution.family == "Gentoo") and LC.fs.is_file("/etc/ssl/certs/ca-certificates.crt") then
        fh:write("smtpd_tls_CAfile = /etc/ssl/certs/ca-certificates.crt\n")
      elseif LC.distribution.family == "SUSE" and LC.fs.is_file("/etc/ssl/ca-bundle.pem") then
        fh:write("smtpd_tls_CAfile = /etc/ssl/ca-bundle.pem\n")
      elseif LC.distribution.family == "RedHat" and LC.fs.is_file("/etc/pki/tls/certs/ca-bundle.crt") then
        fh:write("smtpd_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt\n")
      end
      if v_major > 2 or (v_major == 2 and v_minor >= 6) then
        fh:write("smtpd_tls_protocols = !SSLv2\n")
        fh:write("smtpd_tls_ciphers = medium\n")
        fh:write("smtpd_tls_exclude_ciphers = aNULL, eNULL, ADH\n")
      end
      if v_major > 2 or (v_major == 2 and v_minor >= 5) then
        fh:write("smtpd_tls_mandatory_protocols = !SSLv2\n")
      else
        fh:write("smtpd_tls_mandatory_protocols = SSLv3, TLSv1\n")
      end
      if LC.bits.band(opts.sslmode, 8) > 0 then
        -- PCI compliant ciphers (actually, defending BEAST is not necessary on SMTP, but most dumb PCI scans don't care :(
        fh:write("smtpd_tls_mandatory_ciphers = high\n")
        fh:write("tls_high_cipherlist = ", LC.liveconfig.DEFAULT_SSL_PCI_CIPHERS, "\n")
      else
        fh:write("smtpd_tls_mandatory_ciphers = medium\n")
        fh:write("smtpd_tls_mandatory_exclude_ciphers = aNULL, eNULL, ADH\n")
      end
      fh:write("\n")
    end

    -- 'aliases' file:
    fh:write([[
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
]])
    -- if /etc/aliases doesn't exist yet, create it:
    if not LC.fs.is_file("/etc/aliases") then
      local fha, msg = io.open("/etc/aliases", "w")
      if fha == nil then
        LC.log.print(LC.log.ERR, "Can't create '/etc/aliases' for writing: ", msg)
      else
        fha:write([[# /etc/aliases
mailer-daemon: postmaster
postmaster: root
nobody: root
hostmaster: root
usenet: root
news: root
webmaster: root
www: root
ftp: root
abuse: root
noc: root
security: root
]])
        fha:close()
        -- adjust permissions
        LC.fs.setperm("/etc/aliases", 644, "root", "root")
      end
    end
    -- check if hash file exists:
    if not LC.fs.is_file("/etc/aliases.db") then
      os.execute("/usr/bin/newaliases")
    end

    local hostname = LC.sys.get_fqdn()
    if hostname == nil then hostname = "localhost" end
    fh:write("myhostname = ", hostname, "\n")

    if LC.fs.is_file("/etc/mailname") then
      fh:write("myorigin = /etc/mailname\n")
    else
      fh:write("# myorigin = $myhostname\n")
    end

    fh:write([[

mydestination = localhost.localdomain, localhost, $myhostname
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
recipient_delimiter = +
disable_vrfy_command = yes
]])

    -- outbound IPs
    if opts.out_ipv4 then
      fh:write("smtp_bind_address = ", opts.out_ipv4, "\n")
    end
    if opts.out_ipv6 and opts.out_ipv6 ~= "" then
      fh:write("smtp_bind_address6 = ", opts.out_ipv6, "\n")
    end

    fh:write("\n")

    if LC.distribution.family == "SUSE" then
      -- some OpenSUSE specific settings:
      fh:write([[
setgid_group = maildrop
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/lib/postfix
data_directory = /var/lib/postfix
mail_owner = postfix

]])
    end

    fh:write([[
virtual_mailbox_domains = hash:/etc/postfix/virtual_domains
virtual_mailbox_base = /var/mail
virtual_alias_maps = hash:/etc/postfix/virtual_alias
virtual_mailbox_maps = hash:/etc/postfix/virtual_alias
show_user_unknown_table_name = no
]])
    fh:write("virtual_minimum_uid = ", uid, "\n")
    fh:write("virtual_uid_maps = static:", uid, "\n")
    fh:write("virtual_gid_maps = static:", gid, "\n")
    fh:write([[
virtual_transport = dovecot
dovecot_destination_recipient_limit = 1
mailbox_size_limit = 0

smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $mydomain
broken_sasl_auth_clients = yes

smtpd_helo_required = yes
smtpd_helo_restrictions = reject_invalid_helo_hostname
smtpd_client_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_invalid_hostname,
    reject_unknown_reverse_client_hostname]])
    -- table with list of RBLs to check
    if type(opts.dnsbl) == "table" then
      local i, s
      for i, s in ipairs(opts.dnsbl) do
        fh:write(",\n    reject_rbl_client ", s)
      end
    end
    fh:write("\n")

    fh:write([[
smtpd_sender_restrictions =
    permit_mynetworks,
    reject_unknown_address,
    reject_unknown_sender_domain,
    reject_non_fqdn_sender,
    check_sender_access hash:/etc/postfix/sender_access
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_unknown_recipient_domain,
    check_recipient_access hash:/etc/postfix/recipient_access]])
    -- Greylisting enabled?
    if opts.greylist then
      -- table with list of DNS Whitelists (Postfix 2.8+)
      if (v_major > 2 or (v_major == 2 and v_minor >= 8)) and type(opts.dnswl) == "table" then
        local i, s
        for i, s in ipairs(opts.dnsbl) do
          fh:write(",\n    permit_dnswl_client ", s)
        end
      end
      fh:write(",\n    check_recipient_access hash:/etc/postfix/greylist_addrs")
    end
    fh:write("\n")

    fh:write([[
smtpd_discard_ehlo_keywords = silent-discard, dsn
smtpd_recipient_limit = 250
]])

    if v_major > 2 or (v_major == 2 and v_minor >= 10) then
      fh:write("smtpd_relay_restrictions = \n")
    end

    fh:write("\n")

    if opts.msgsize ~= nil then
      fh:write("# maximum message size: ", opts.msgsize, " MB\n")
      fh:write("message_size_limit = ", (opts.msgsize * 1024 * 1024), "\n")
    else
      fh:write("# maximum message size: 25 MB (default)\n")
      fh:write("message_size_limit = 26214400\n")
    end
    fh:write("\n")

    -- check if antivirus software (via milter) is to be configured:
    if opts.antivirus then
      fh:write("# check all e-mails for viruses using clamav-milter:\n")
      fh:write("smtpd_milters = ", cfg["clamav_milter_socket"], "\n\n")
      
      -- adjust clamav-milter.conf
      os.execute("sed -i -e 's/^#\?OnInfected .*$/OnInfected Reject/i' " .. cfg["clamav_milter_cfg"])
    end

    -- check if greylisting is enabled:
    if opts.greylist then
      fh:write("smtpd_restriction_classes = greylist\n")
      if LC.distribution.family == "Debian" then
        fh:write("greylist = check_policy_service inet:127.0.0.1:10023\n")
      elseif LC.distribution.family == "SUSE" or LC.distribution.family == "RedHat" then
        fh:write("greylist = check_policy_service unix:/var/spool/postfix/postgrey/socket\n")
      elseif LC.distribution.family == "Gentoo" then
        fh:write("greylist = check_policy_service inet:127.0.0.1:10030\n")
      end
      fh:write("\n")
      if not LC.fs.is_file(greylist_file .. ".db") then
        if not LC.fs.is_file(greylist_file) then
          local fha, msg = io.open(greylist_file, "w")
          if fha == nil then
            LC.log.print(LC.log.ERR, "Can't create '" .. greylist_file .. "' for writing: ", msg)
          else
            LC.liveconfig.writeHeader(fha)
          end
          fha:close()
          -- adjust permissions
          LC.fs.setperm(greylist_file, 640, "root", "postfix")
        end

        -- update map file
        os.execute("/usr/sbin/postmap " .. greylist_file)
      end
    end

    LC.liveconfig.writeFooter(fh)
    fh:close()

    -- enable configuration
    LC.fs.rename(configfile .. ".tmp", configfile)

    -- create "master.cf" configuration file
    fh, msg = io.open(masterfile .. ".tmp", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", masterfile, ".tmp' for writing: ", msg)
      return false, "Can't open '" .. masterfile .. ".tmp' for writing: " .. msg
    end
    -- adjust owner & permissions - only Postfix needs to read this file:
    LC.fs.setperm(masterfile .. ".tmp", 640, "root", "postfix")
    LC.liveconfig.writeHeader(fh)

    fh:write([[

# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (yes)   (never) (100)
# ==========================================================================
smtp      inet  n       -       n       -       -       smtpd
submission inet n       -       n       -       -       smtpd
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
]])

    if opts.ssl and opts.sslmode ~= nil and LC.bits.band(opts.sslmode, 2) > 0 then
      -- enable (non-standard) SMTPS port
      -- we use the explicit port number here (465), because many distributions
      -- have already removed "smtps" from /etc/services
      fh:write([[
465       inet  n       -       n       -       -       smtpd
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
]])
    end

    fh:write([[
pickup    fifo  n       -       -       60      1       pickup
cleanup   unix  n       -       -       -       0       cleanup
qmgr      fifo  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       -       1000?   1       tlsmgr
rewrite   unix  -       -       -       -       -       trivial-rewrite
bounce    unix  -       -       -       -       0       bounce
defer     unix  -       -       -       -       0       bounce
trace     unix  -       -       -       -       0       bounce
verify    unix  -       -       -       -       1       verify
flush     unix  n       -       -       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
]])

    if opts.out_ipv6 and opts.out_ipv6 == "" then
      -- disable IPv6 for outbound connections
      fh:write("  -o inet_protocols=ipv4\n")
      fh:write("  -o inet_interfaces=all\n")
    end

    fh:write([[
# When relaying mail as backup MX, disable fallback_relay to avoid MX loops
relay     unix  -       -       -       -       -       smtp
        -o smtp_fallback_relay=
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       -       -       -       showq
error     unix  -       -       -       -       -       error
retry     unix  -       -       -       -       -       error
discard   unix  -       -       -       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       -       -       -       lmtp
anvil     unix  -       -       -       -       1       anvil
scache    unix  -       -       -       -       1       scache

maildrop  unix  -       n       n       -       -       pipe
  flags=DROhu user=vmail argv=/usr/bin/maildrop -d ${recipient}

dovecot   unix  -       n       n       -       -       pipe
]])

    if LC.fs.is_file("/usr/libexec/dovecot/deliver") then
      fh:write("  flags=DROhu user=mail:mail argv=/usr/libexec/dovecot/deliver -f ${sender} -d ${recipient} -e\n")
    else
      fh:write("  flags=DROhu user=mail:mail argv=/usr/lib/dovecot/deliver -f ${sender} -d ${recipient} -e\n")
    end

    fh:write("\n")

    LC.liveconfig.writeFooter(fh)
    fh:close()

    -- enable master.cf configuration
    LC.fs.rename(masterfile .. ".tmp", masterfile)
  end -- if not NOUPDATE

  -- create virtual_domains file (if not existing)
  if not LC.fs.is_file(domainsfile) then
    local fh, msg = io.open(domainsfile .. ".tmp", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", domainsfile .. ".tmp", "' for writing: ", msg)
      return false, "Can't open '" .. domainsfile .. ".tmp" .. "' for writing: " .. msg
    end
    -- adjust owner & permissions - only Postfix needs to read this file:
    LC.fs.setperm(domainsfile .. ".tmp", 640, "root", "postfix")
    LC.liveconfig.writeHeader(fh)
    fh:close()
    LC.fs.rename(domainsfile .. ".tmp", domainsfile)
  end
  os.execute("/usr/sbin/postmap " .. domainsfile)

  -- create virtual_alias file (if not existing)
  if not LC.fs.is_file(aliasfile) then
    local fh, msg = io.open(aliasfile .. ".tmp", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", aliasfile .. ".tmp", "' for writing: ", msg)
      return false, "Can't open '" .. aliasfile .. ".tmp" .. "' for writing: " .. msg
    end
    -- adjust owner & permissions - only Postfix needs to read this file:
    LC.fs.setperm(aliasfile .. ".tmp", 640, "root", "postfix")
    LC.liveconfig.writeHeader(fh)
    fh:close()
    LC.fs.rename(aliasfile .. ".tmp", aliasfile)
  end
  os.execute("/usr/sbin/postmap " .. aliasfile)

  -- create sender_access file (if not existing)
  if not LC.fs.is_file(sender_access_file) then
    local fh, msg = io.open(sender_access_file .. ".tmp", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", sender_access_file .. ".tmp", "' for writing: ", msg)
      return false, "Can't open '" .. sender_access_file .. ".tmp" .. "' for writing: " .. msg
    end
    -- adjust owner & permissions - only Postfix needs to read this file:
    LC.fs.setperm(sender_access_file .. ".tmp", 640, "root", "postfix")
    LC.liveconfig.writeHeader(fh)
    fh:close()
    LC.fs.rename(sender_access_file .. ".tmp", sender_access_file)
  end
  os.execute("/usr/sbin/postmap " .. sender_access_file)

  -- create recipient_access file (if not existing)
  if not LC.fs.is_file(recipient_access_file) then
    local fh, msg = io.open(recipient_access_file .. ".tmp", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", recipient_access_file .. ".tmp", "' for writing: ", msg)
      return false, "Can't open '" .. recipient_access_file .. ".tmp" .. "' for writing: " .. msg
    end
    -- adjust owner & permissions - only Postfix needs to read this file:
    LC.fs.setperm(recipient_access_file .. ".tmp", 640, "root", "postfix")
    LC.liveconfig.writeHeader(fh)
    fh:close()
    LC.fs.rename(recipient_access_file .. ".tmp", recipient_access_file)
  end
  os.execute("/usr/sbin/postmap " .. recipient_access_file)

  -- update status file
  LC.liveconfig.writeStatus(statusfile, "postfix", opts.revision, os.date("%Y-%m-%d %H:%M:%S %Z"))

  return true
end

-- ---------------------------------------------------------------------------
-- convert an e-mail address into a search pattern:
local function search_addr(addr)
  s = "^" .. addr .. "%s"
  s = string.gsub(s, "%.", "%%.")
  s = string.gsub(s, "%-", "%%-")
  return s
end

-- ---------------------------------------------------------------------------
-- addMailbox
--
-- Add a mailbox to postfix server
-- ---------------------------------------------------------------------------
function addMailbox(cfg, opts, data)

  local domainsfile = cfg["domainsfile"]
  local aliasfile   = cfg["aliasfile"]
  if opts and opts.prefix then
    domainsfile   = opts.prefix .. domainsfile
    aliasfile     = opts.prefix .. aliasfile
    configpath  = opts.prefix .. configpath
  end
  local greylist_file = cfg["configpath"] .. "/greylist_addrs"
  local name = data.name
  -- if a catch-all-address is configured, replace '*' with '':
  if name == '*' then name = '' end

  -- add domain to 'domains' file
  local fhr, fhw, msg
  fhr, msg = io.open(domainsfile, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", domainsfile, "' for reading: ", msg)
    return false, "Can't open '" .. domainsfile .. "' for reading: " .. msg
  end

  fhw, msg = io.open(domainsfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", domainsfile .. ".tmp", "' for writing: ", msg)
    fhr:close()
    return false, "Can't open '" .. domainsfile .. ".tmp" .. "' for writing: " .. msg
  end
  -- adjust owner & permissions - only Postfix needs to read this file:
  LC.fs.setperm(domainsfile .. ".tmp", 640, "root", "postfix")

  local search = "^" .. data.domain
  search = string.gsub(search, "%.", "%%.")
  search = string.gsub(search, "%-", "%%-")

  local line
  local found = false
  while true do
    line = fhr:read()
    if line == nil then break end
    if string.find(line, search .. "$") ~= nil or string.find(line, search .. "%s") ~= nil then
      found = true
      break
    end
    fhw:write(line)
    fhw:write("\n")
  end

  fhr:close()

  if found == true then
    -- entry already in domains file:
    fhw:close()
    os.remove(domainsfile .. ".tmp")
  else
    -- entry not found, so add new one:
    fhw:write(data.domain, "\t", data.domain, "\n")
    fhw:close()
    LC.fs.rename(domainsfile .. ".tmp", domainsfile)
    LC.timeout.set('postfix.update_virtual_domains', 10, 60)
  end

  -- modify "virtual_alias" file:
  -- - add aliases
  -- - add forwards
  local fhr, fhw, msg
  fhr, msg = io.open(aliasfile, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", aliasfile, "' for reading: ", msg)
    return false, "Can't open '" .. aliasfile .. "' for reading: " .. msg
  end

  fhw, msg = io.open(aliasfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", aliasfile .. ".tmp", "' for writing: ", msg)
    fhr:close()
    return false, "Can't open '" .. aliasfile .. ".tmp" .. "' for writing: " .. msg
  end
  -- adjust owner & permissions - only Postfix needs to read this file:
  LC.fs.setperm(aliasfile .. ".tmp", 640, "root", "postfix")

  -- create list with search patterns
  search = { }
  search[1] = search_addr(name .. "@" .. data.domain)
  local i, s
  
  -- add aliases to search list
  if type(data.aliases) == "table" then
    for i, s in ipairs(data.aliases) do
      search[#search + 1] = search_addr(s .. "@" .. data.domain)
    end
  end
  -- add aliases to be deleted to search list
  if type(data.delaliases) == "table" then
    for i, s in ipairs(data.delaliases) do
      search[#search + 1] = search_addr(s .. "@" .. data.domain)
    end
  end

  -- add "old" mailbox name to search list (if mailbox is renamed)
  if data.old_addr ~= nil then
    search[#search + 1] = search_addr(data.old_addr)
    local at_pos = data.old_addr:find("@")
    if at_pos ~= nil then
      local old_domain = data.old_addr:sub(at_pos+1)
      -- add aliases to search list
      if type(data.aliases) == "table" then
        for i, s in ipairs(data.aliases) do
          search[#search + 1] = search_addr(s .. "@" .. old_domain)
        end
      end
      -- add aliases to be deleted to search list
      if type(data.delaliases) == "table" then
        for i, s in ipairs(data.delaliases) do
          search[#search + 1] = search_addr(s .. "@" .. old_domain)
        end
      end

    end
  end

  while true do
    line = fhr:read()
    if line == nil then break end
--    LC.log.print(LC.log.DEBUG, "Line: '" .. line .. "'")
    found = false
    for i, s in ipairs(search) do
      if string.find(line, s) ~= nil then
        found = true
--        LC.log.print(LC.log.DEBUG, "FOUND: " .. line .. "'")
        break
      end
    end
    if found == false then
      -- only write line if not matched
      fhw:write(line, "\n")
    end
  end

  fhr:close()

  -- write forwards (if defined)
  if type(data.forwards) == "table" then
    fhw:write(name, "@", data.domain, "\t")
    if data.mailbox == true and name ~= '' then
      -- save copy to local mailbox
      fhw:write(name, "@", data.domain, ", ")
    end
    for i, s in ipairs(data.forwards) do
      if i > 1 then
        fhw:write(", ", s)
      else
        fhw:write(s)
      end
    end
    fhw:write("\n")
  elseif data.mailbox == true and name ~= '' then
    -- if no forwards are defined and this is a real mailbox, write also an alias
    -- entry pointing to itself (to allow local mailboxes while catch-all addresses may exist)
    fhw:write(name, "@", data.domain, "\t", name, "@", data.domain, "\n")
  end

  -- now add all aliases:
  if type(data.aliases) == "table" and name ~= '' then
    for i, s in ipairs(data.aliases) do
      fhw:write(s, "@", data.domain, "\t", name, "@", data.domain, "\n")
    end
  end

  fhw:close()
  LC.fs.rename(aliasfile .. ".tmp", aliasfile)

  -- update map file
  LC.timeout.set('postfix.update_virtual_alias', 10, 60)

  if LC.fs.is_file(greylist_file) then
    -- update greylisting file
    fhr, msg = io.open(greylist_file, "r")
    if fhr == nil then
      LC.log.print(LC.log.ERR, "Can't open '", greylist_file, "' for reading: ", msg)
      return false, "Can't open '" .. greylist_file .. "' for reading: " .. msg
    end

    fhw, msg = io.open(greylist_file .. ".tmp", "w")
    if fhw == nil then
      LC.log.print(LC.log.ERR, "Can't open '", greylist_file .. ".tmp", "' for writing: ", msg)
      fhr:close()
      return false, "Can't open '" .. greylist_file .. ".tmp" .. "' for writing: " .. msg
    end
    -- adjust owner & permissions - only Postfix needs to read this file:
    LC.fs.setperm(greylist_file .. ".tmp", 640, "root", "postfix")

    while true do
      line = fhr:read()
      if line == nil then break end
      found = false
      for i, s in ipairs(search) do
        if string.find(line, s) ~= nil then
          found = true
          break
        end
      end
      if found == false then
        -- only write line if not matched
        fhw:write(line, "\n")
      end
    end
    fhr:close()

    -- if greylisting is enabled, add all addresses/aliases:
    if data.greylist then
      fhw:write(name, "@", data.domain, "\tgreylist\n")
      -- now add all aliases:
      if type(data.aliases) == "table" and name ~= '' then
        for i, s in ipairs(data.aliases) do
          fhw:write(s, "@", data.domain, "\tgreylist\n")
        end
      end
    end

    fhw:close()
    LC.fs.rename(greylist_file .. ".tmp", greylist_file)

    -- update map file
    LC.timeout.set('postfix.update_greylist_addrs', 10, 60)

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
-- removeLine
--
-- Remove a line from given map file
-- ---------------------------------------------------------------------------
local function removeLine(filename, domain)
  local fhr, fhw, msg, line
  fhr, msg = io.open(filename, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", filename, "' for reading: ", msg)
    return false
  end

  fhw, msg = io.open(filename .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", filename .. ".tmp", "' for writing: ", msg)
    fhr:close()
    return false
  end
  -- adjust owner & permissions - only Postfix needs to read this file:
  LC.fs.setperm(filename .. ".tmp", 640, "root", "postfix")

  local found = false
  local search = "^" .. domain
  search = string.gsub(search, "%.", "%%.")
  search = string.gsub(search, "%-", "%%-")

  while true do
    line = fhr:read()
    if line == nil then break end
    if string.find(line, search .. "$") ~= nil or string.find(line, search .. "%s") ~= nil then
      found = true
    else
      -- only write line if not matched
      fhw:write(line)
      fhw:write("\n")
    end
  end

  fhr:close()

  fhw:close()

  if found then
    LC.fs.rename(filename .. ".tmp", filename)
    return true
  else
    os.remove(filename .. ".tmp")
    return false
  end

end

-- ---------------------------------------------------------------------------
-- deleteMailbox
--
-- Delete mailbox
-- ---------------------------------------------------------------------------
function deleteMailbox(cfg, opts, data)

  local domainsfile = cfg["domainsfile"]
  local aliasfile   = cfg["aliasfile"]
  local configpath  = cfg["configpath"]
  if opts and opts.prefix then
    domainsfile = opts.prefix .. domainsfile
    aliasfile   = opts.prefix .. aliasfile
    configpath  = opts.prefix .. configpath
  end
  local sender_access_file = cfg["configpath"] .. "/sender_access"
  local recipient_access_file = cfg["configpath"] .. "/recipient_access"
  local greylist_file = cfg["configpath"] .. "/greylist_addrs"

  -- if a catch-all-address is configured, replace '*' with '':
  local name = data.name
  if name == '*' then name = '' end

  -- modify "virtual_alias" file:
  -- - remove aliases
  -- - remove forwards
  local fhr, fhw, msg, line
  fhr, msg = io.open(aliasfile, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", aliasfile, "' for reading: ", msg)
    return false, "Can't open '" .. aliasfile .. "' for reading: " .. msg
  end

  fhw, msg = io.open(aliasfile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", aliasfile .. ".tmp", "' for writing: ", msg)
    fhr:close()
    return false, "Can't open '" .. aliasfile .. ".tmp" .. "' for writing: " .. msg
  end
  -- adjust owner & permissions - only Postfix needs to read this file:
  LC.fs.setperm(aliasfile .. ".tmp", 640, "root", "postfix")

  -- create list with search patterns
  search = { }
  search[1] = search_addr(name .. "@" .. data.domain)
  local i, s
  
  -- add aliases to be deleted to search list
  if type(data.delaliases) == "table" then
    for i, s in ipairs(data.delaliases) do
      search[#search + 1] = search_addr(s .. "@" .. data.domain)
    end
  end

  -- count how many mailboxes with this domain are still configured.
  -- if "last" mailbox is deleted, remove also from virtual_domains file:
  local domaincount = 0
  local found = false
  local ds = data.domain
  ds = string.gsub(ds, "%.", "%%.")
  ds = string.gsub(ds, "%-", "%%-")
  ds = "^%S*@" .. ds .. "%s"

  while true do
    line = fhr:read()
    if line == nil then break end
--    LC.log.print(LC.log.DEBUG, "Line: '" .. line .. "'")
    found = false
    for i, s in ipairs(search) do
      if string.find(line, s) ~= nil then
        found = true
--        LC.log.print(LC.log.DEBUG, "FOUND: " .. line .. "'")
        break
      end
    end
    if found == false then
      if string.find(line, ds) ~= nil then
        domaincount = domaincount + 1
      end
      -- only write line if not matched
      fhw:write(line, "\n")
    end
  end

  fhr:close()

  fhw:close()
  LC.fs.rename(aliasfile .. ".tmp", aliasfile)

  -- update map file
  LC.timeout.set('postfix.update_virtual_alias', 10, 60)

  if domaincount == 0 then
    -- deleted last mailbox with this domain, so also remove domain from virtual_aliases, sender_access and recipient_access
    if removeLine(domainsfile, data.domain) then
      LC.timeout.set('postfix.update_virtual_domains', 10, 60)
    end
    if LC.fs.is_file(sender_access_file) and removeLine(sender_access_file, '@' .. data.domain) then
      LC.timeout.set('postfix.update_sender_access', 10, 60)
    end
    if LC.fs.is_file(recipient_access_file) and removeLine(recipient_access_file, '@' .. data.domain) then
      LC.timeout.set('postfix.update_recipient_access', 10, 60)
    end
  end

  if LC.fs.is_file(greylist_file) then
    fhr, msg = io.open(greylist_file, "r")
    if fhr == nil then
      LC.log.print(LC.log.ERR, "Can't open '", greylist_file, "' for reading: ", msg)
      return false, "Can't open '" .. greylist_file .. "' for reading: " .. msg
    end

    fhw, msg = io.open(greylist_file .. ".tmp", "w")
    if fhw == nil then
      LC.log.print(LC.log.ERR, "Can't open '", greylist_file .. ".tmp", "' for writing: ", msg)
      fhr:close()
      return false, "Can't open '" .. greylist_file .. ".tmp" .. "' for writing: " .. msg
    end
    -- adjust owner & permissions - only Postfix needs to read this file:
    LC.fs.setperm(greylist_file .. ".tmp", 640, "root", "postfix")

    while true do
      line = fhr:read()
      if line == nil then break end
      found = false
      for i, s in ipairs(search) do
        if string.find(line, s) ~= nil then
          found = true
          break
        end
      end
      if found == false then
        -- only write line if not matched
        fhw:write(line, "\n")
      end
    end

    fhr:close()

    fhw:close()
    LC.fs.rename(greylist_file .. ".tmp", greylist_file)

    -- update map file
    LC.timeout.set('postfix.update_greylist_addrs', 10, 60)

  end

  return true

end

-- ---------------------------------------------------------------------------
-- update_virtual_alias()
--
-- Update "virtual_alias" map file
-- ---------------------------------------------------------------------------
function update_virtual_alias()
  LC.log.print(LC.log.DEBUG, "postfix.update_virtual_alias() called")
  -- get configuration
  local cfg = LC.smtp.getConfig('postfix')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "postfix.update_virtual_alias(): no configuration for 'postfix' available!?")
    return
  end
  -- get filename
  if cfg.aliasfile == nil then
    LC.log.print(LC.log.ERR, "postfix.update_virtual_alias(): no aliasfile for 'postfix' available!?")
    return
  end

  -- update map file
  os.execute("/usr/sbin/postmap " .. cfg.aliasfile)

end

-- ---------------------------------------------------------------------------
-- update_virtual_domains()
--
-- Update "virtual_domains" map file
-- ---------------------------------------------------------------------------
function update_virtual_domains()
  LC.log.print(LC.log.DEBUG, "postfix.update_virtual_domains() called")
  -- get configuration
  local cfg = LC.smtp.getConfig('postfix')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "postfix.update_virtual_domains(): no configuration for 'postfix' available!?")
    return
  end
  -- get filename
  if cfg.domainsfile == nil then
    LC.log.print(LC.log.ERR, "postfix.update_virtual_domains(): no domainsfile for 'postfix' available!?")
    return
  end

  -- update map file
  os.execute("/usr/sbin/postmap " .. cfg.domainsfile)

end

-- ---------------------------------------------------------------------------
-- update_sender_access()
--
-- Update "sender_access" map file
-- ---------------------------------------------------------------------------
function update_sender_access()
  LC.log.print(LC.log.DEBUG, "postfix.update_sender_access() called")
  -- get configuration
  local cfg = LC.smtp.getConfig('postfix')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "postfix.update_sender_access(): no configuration for 'postfix' available!?")
    return
  end

  -- update map file
  os.execute("/usr/sbin/postmap " .. cfg.configpath .. "/sender_access")

end

-- ---------------------------------------------------------------------------
-- update_recipient_access()
--
-- Update "recipient_access" map file
-- ---------------------------------------------------------------------------
function update_recipient_access()
  LC.log.print(LC.log.DEBUG, "postfix.update_recipient_access() called")
  -- get configuration
  local cfg = LC.smtp.getConfig('postfix')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "postfix.update_recipient_access(): no configuration for 'postfix' available!?")
    return
  end

  -- update map file
  os.execute("/usr/sbin/postmap " .. cfg.configpath .. "/recipient_access")

end

-- ---------------------------------------------------------------------------
-- update_greylist_addrs()
--
-- Update "greylist_addrs" map file
-- ---------------------------------------------------------------------------
function update_greylist_addrs()
  LC.log.print(LC.log.DEBUG, "postfix.update_greylist_addrs() called")
  -- get configuration
  local cfg = LC.smtp.getConfig('postfix')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "postfix.update_greylist_addrs(): no configuration for 'postfix' available!?")
    return
  end

  -- update map file
  os.execute("/usr/sbin/postmap /etc/postfix/greylist_addrs")

end

-- ---------------------------------------------------------------------------
-- lockDomains()
--
-- Lock domains (forbid sending of e-mails)
-- ---------------------------------------------------------------------------
function lockDomains(domains)
  LC.log.print(LC.log.DEBUG, "postfix.lockDomains() called")
  -- get configuration
  local cfg = LC.smtp.getConfig('postfix')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "postfix.update_sender_access(): no configuration for 'postfix' available!?")
    return
  end

  local filename = cfg.configpath .. "/sender_access"

  local fhr, fhw, msg, line
  fhr, msg = io.open(filename, "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", filename, "' for reading: ", msg)
    return false, "Can't open '" .. filename .. "' for reading: " .. msg
  end

  fhw, msg = io.open(filename .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", filename .. ".tmp", "' for writing: ", msg)
    fhr:close()
    return false, "Can't open '" .. filename .. ".tmp" .. "' for writing: " .. msg
  end
  -- adjust owner & permissions - only Postfix needs to read this file:
  LC.fs.setperm(filename .. ".tmp", 640, "root", "postfix")

  -- create list with search patterns
  local search = { }
  local i, s, p
  for i, s in ipairs(domains) do
    p = "^@" .. s .. "%s"
    p = string.gsub(p, "%.", "%%.")
    p = string.gsub(p, "%-", "%%-")
    search[s] = p
  end

  while true do
    line = fhr:read()
    if line == nil then break end
    for i, s in pairs(search) do
      if string.find(line, s) ~= nil then
        -- domain found, so remove pattern from list
        search[i] = nil
        break
      end
    end
    fhw:write(line, "\n")
  end

  fhr:close()

  -- append all domains left in list to the file:
  local modified = false
  for i, s in pairs(search) do
    fhw:write("@", i, "\t500 No outbound mails allowed - please contact your administrator.\n")
    modified = true
  end

  fhw:close()

  if modified then
    LC.fs.rename(filename .. ".tmp", filename)
    -- update map file
    LC.timeout.set('postfix.update_sender_access', 10, 60)
  end

  return true

end

-- ---------------------------------------------------------------------------
-- update_lclogparse
--
-- Create/update lclogparse configuration
-- ---------------------------------------------------------------------------
function update_lclogparse(cfg)
  if cfg == nil or cfg.logfile == nil or not LC.fs.is_file(cfg.logfile) then return end
  local rules = [=[	# Postfix
	NEW:	IEa	^.* postfix/smtpd\[[[:digit:]]+\]: ([A-F0-9]+): (client=[^,]+), sasl_method=[^,]+, sasl_username=([^ ]+)
	NEW:	IE	^.* postfix/smtpd\[[[:digit:]]+\]: ([A-F0-9]+): (client=[^,]+)$
	UPDATE:	IS	^.* postfix/.*: ([A-F0-9]+): from=<[^>]+>, size=(\d+)
	UPDATE:	IOa--	^.* postfix/.*: ([A-F0-9]+): (to)=<([^>]+)>, relay=(?!dovecot).*, status=(sent|bounced)
	UPDATE:	IOa--	^.* postfix/.*: ([A-F0-9]+): (to)=<[^>]+>, orig_to=<([^>]+)>, relay=(?!dovecot).*, status=(sent|bounced)
	UPDATE:	Ia	^.* postfix/.*: ([A-F0-9]+): to=<([^>]+)>, relay=dovecot
	UPDATE:	Ia	^.* postfix/.*: ([A-F0-9]+): to=<[^>]+>, orig_to=<([^>]+)>, relay=dovecot
	DONE:	I	^.* postfix/.*: ([A-F0-9]+): removed
	OUTPUT-FILE:	]=] .. LC.liveconfig.localstatedir .. [=[/lib/liveconfig/smtp.stats
]=]
  LC.liveconfig.update_lclogparse(cfg.logfile, rules)
end

-- <EOF>----------------------------------------------------------------------
