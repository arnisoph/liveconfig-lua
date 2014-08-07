--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2013 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/bind.lua
-- Lua module to manage BIND DNS server
-- $Id: bind.lua 2702 2013-12-09 08:31:31Z kk $
-- ---------------------------------------------------------------------------
-- This is the "driver" module for ISC BIND DNS server.
-- It must be loaded by the command
--   LC.dns.load("bind")
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
local table = table
local tonumber = tonumber
local pairs = pairs

-- Module declaration
module("bind")

-- Exported functions
--   detect()
--   install()
--   uninstall()
--   configure()
--   updateKeys()
--   addZone()
--   updateZone()
--   delZone()
--   reconfig()
--   restart()

-- ---------------------------------------------------------------------------
-- getBinaryVersion()
--
-- Return the binary version number from bind
-- ---------------------------------------------------------------------------
local function getBinaryVersion(bin)
  local handle = io.popen(bin .. " -v", "r")
  local ret = handle:read("*a")
  handle:close()
  local v = string.match(ret, "BIND%s(%d+%.%d+[%.%d+]*)")
  return v
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect if an bind server is installed. If yes, return a table containing
-- all relevant informations:
--   type          => "bind"
--   binname       => file name of the bind server binary (eg. "/usr/sbin/bind")
--   binversion    => binary version (eg. "2.2.3")
--   pkgname       => name of the package (see below)
--   pkgversion    => package version number (eg. "2.2.3-4+etch11")
--   cfgfileowner  => Owner of config files (eg. "root")
--   cfgfilegroup  => Group of config files (eg. "bind")
--   configfile    => LiveConfigs' configuration file (snippet)
--   start_cmd     => command to start bind
--   stop_cmd      => command to stop bind
--   reload_cmd    => command to re-load configuration
--   restart_cmd   => command to re-start bind process
--
-- If pkgversion is 'nil', then bind server was most propably not installed
-- as native distribution package, but compiled/installed manually.
-- ---------------------------------------------------------------------------
function detect()

  local pkg, v
  -- first check for distribution-specific packages
  if LC.distribution.family == "Debian" then
    -- Debian/Ubuntu
    pkg, v = LC.distribution.hasPackage('bind9')
  elseif LC.distribution.family == "BSD" then
    pkg, v = LC.distribution.hasPackage('bind96', 'bind98', 'bind99')
    if pkg == nil then
      -- check for bundled BIND
      if LC.fs.is_file("/usr/sbin/named") and LC.fs.is_dir("/etc/namedb") then
        pkg = "bind (bundled)"
        v = getBinaryVersion("/usr/sbin/named")
      end
    end
  else
    pkg, v = LC.distribution.hasPackage('bind')
  end
  if pkg ~= nil then
    LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
    local bin = "/usr/sbin/named"
    local bv = getBinaryVersion(bin)
    if bv ~= nil then
      if LC.distribution.family == "Debian" then
        -- Debian/Ubuntu Linux
        local data = {
          ["type"]          = "bind",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["cfgfileowner"]  = 'root',
          ["cfgfilegroup"]  = 'bind',
          ["configpath"]    = "/etc/bind",
          ["configfile"]    = "/etc/bind/named.conf.options",
          ["zonefile"]      = "/etc/bind/zones.liveconfig",
          ["statsfile"]     = "/var/run/named/named.stats",
          ["statusfile"]    = "/etc/bind/liveconfig.status",
          ["zonepath"]      = "/var/lib/bind",
          ["cachepath"]     = "/var/cache/bind",
          ["start_cmd"]     = "/etc/init.d/bind9 start",
          ["stop_cmd"]      = "/etc/init.d/bind9 stop",
          ["reload_cmd"]    = "/etc/init.d/bind9 reload",
          ["restart_cmd"]   = "/etc/init.d/bind9 restart",
          ["reconfig_cmd"]  = "/usr/sbin/rndc reconfig",
        }
        return data
      elseif LC.distribution.family == "Gentoo" then
        -- Gentoo Linux
        local data = {
          ["type"]          = "bind",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["cfgfileowner"]  = 'root',
          ["cfgfilegroup"]  = 'named',
          ["configpath"]    = "/etc/bind",
          ["configfile"]    = "/etc/bind/named.conf",
          ["zonefile"]      = "/etc/bind/zones.liveconfig",
          ["statsfile"]     = "/var/stats/named.stats",
          ["statusfile"]    = "/etc/bind/liveconfig.status",
          ["zonepath"]      = "/var/bind/pri",
          ["cachepath"]     = "/var/bind",
          ["start_cmd"]     = "/etc/init.d/named start",
          ["stop_cmd"]      = "/etc/init.d/named stop",
          ["reload_cmd"]    = "/etc/init.d/named reload",
          ["restart_cmd"]   = "/etc/init.d/named restart",
          ["reconfig_cmd"]  = "/usr/sbin/rndc reconfig",
        }
        return data
      elseif LC.distribution.family == "RedHat" then
        -- RHEL/CentOS:
        local data = {
          ["type"]          = "bind",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["cfgfileowner"]  = 'root',
          ["cfgfilegroup"]  = 'named',
          ["configpath"]    = "/etc/named",
          ["configfile"]    = "/etc/named.conf",
          ["zonefile"]      = "/etc/named/zones.liveconfig",
          ["statsfile"]     = "/var/named/data/named.stats",
          ["statusfile"]    = "/etc/named/liveconfig.status",
          ["zonepath"]      = "/var/named/dynamic",
          ["cachepath"]     = "/var/named",
          ["start_cmd"]     = "/sbin/service named start",
          ["stop_cmd"]      = "/sbin/service named stop",
          ["reload_cmd"]    = "/sbin/service named reload",
          ["restart_cmd"]   = "/sbin/service named restart",
          ["reconfig_cmd"]  = "/usr/sbin/rndc reconfig",
        }
        return data
      elseif LC.distribution.family == "SUSE" then
        -- OpenSUSE:
        local data = {
          ["type"]          = "bind",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["cfgfileowner"]  = 'root',
          ["cfgfilegroup"]  = 'named',
          ["configpath"]    = "/etc/named.d",
          ["configfile"]    = "/etc/named.conf",
          ["zonefile"]      = "/etc/named.d/zones.liveconfig",
          ["statsfile"]     = "/var/lib/named/log/named.stats",
          ["statusfile"]    = "/etc/named.d/liveconfig.status",
          ["zonepath"]      = "/var/lib/named/dyn",
          ["cachepath"]     = "/var/lib/named",
          ["chrootpath"]    = "/var/lib/named",
          ["start_cmd"]     = "systemctl start named.service",
          ["stop_cmd"]      = "systemctl stop named.service",
          ["reload_cmd"]    = "systemctl reload named.service",
          ["restart_cmd"]   = "systemctl restart named.service",
          ["reconfig_cmd"]  = "/usr/sbin/rndc reconfig",
        }
        return data
      elseif LC.distribution.family == "BSD" then
        local data = {
          ["type"]          = "bind",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["cfgfileowner"]  = 'bind',
          ["cfgfilegroup"]  = 'wheel',
          ["configpath"]    = "/etc/namedb",
          ["configfile"]    = "/etc/namedb/named.conf",
          ["zonefile"]      = "/etc/namedb/zones.liveconfig",
          ["statsfile"]     = "/var/stats/named.stats",
          ["statusfile"]    = "/etc/namedb/liveconfig.status",
          ["zonepath"]      = "/etc/namedb/master",
          ["cachepath"]     = "/etc/namedb/working",
          ["start_cmd"]     = "/etc/rc.d/named start",
          ["stop_cmd"]      = "/etc/rc.d/named stop",
          ["reload_cmd"]    = "/etc/rc.d/named reload",
          ["restart_cmd"]   = "/usr/sbin/rndc stop; sleep 5; /etc/rc.d/named start",
          ["reconfig_cmd"]  = "/usr/sbin/rndc reconfig",
        }
        return data
      end
    end
    -- else: fall trough, to check for custom bind installation
    LC.log.print(LC.log.DEBUG, "LC.bind.detect(): Found bind server package '", pkg, "', but no binary at ", bin)
  end
end

-- ---------------------------------------------------------------------------
-- install(cfg, opts)
--
-- Install LiveConfig configuration files for ISC BIND
-- ---------------------------------------------------------------------------
function install(cfg, opts)
  LC.log.print(LC.log.INFO, "Activating management of ISC BIND")

  local fh, status, msg
  local configpath = cfg["configpath"]
  local configfile = cfg["configfile"]
  local statusfile = cfg["statusfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    statusfile = opts.prefix .. statusfile
  end

  -- create backup of main config file
  if LC.fs.is_file(configfile) then
    if not LC.fs.is_file(configfile .. ".lcbak") then
      -- only back up if not done yet
      LC.fs.rename(configfile, configfile .. ".lcbak")
    end
  end

  -- create (new) config file
  configure(cfg, opts)

  -- write status file
  LC.liveconfig.writeStatus(statusfile, cfg.type, 0, '0000-00-00 00:00:00')

  return true
end

-- ---------------------------------------------------------------------------
-- uninstall(cfg, opts)
--
-- Remove LiveConfig configuration files from ISC BIND
-- ---------------------------------------------------------------------------
function uninstall(cfg, opts)
  LC.log.print(LC.log.INFO, "Disabling management of ISC BIND")

  local status, msg
  local configpath = cfg["configpath"]
  local configfile = cfg["configfile"]
  local statusfile = cfg["statusfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    statusfile = opts.prefix .. statusfile
  end

  -- remove zone list file
  os.remove(configpath .. "/zones.liveconfig")

  -- remove TSIG key file
  os.remove(configpath .. "/keys.liveconfig")

  -- restore original configuration file
  if LC.fs.is_file(configfile .. ".lcbak") then
    LC.fs.rename(configfile .. ".lcbak", configfile)
  end

  -- remove status file
  os.remove(statusfile)

  return true
end

-- ---------------------------------------------------------------------------
-- configure(cfg, opts)
--
-- Configure ISC BIND
-- ---------------------------------------------------------------------------
function configure(cfg, opts)

  local fh, msg, i
  local configfile = cfg["configfile"]
  local configpath = cfg["configpath"]
  local v_major, v_minor, v_patch = string.match(cfg["binversion"], "(%d+)%.(%d+)%.?(%d*)")
  if v_major then
    v_major = tonumber(v_major)
    v_minor = tonumber(v_minor)
    v_patch = tonumber(v_patch)
  else
    v_major = 0
    v_minor = 0
    v_patch = 0
    LC.log.print(LC.log.WARNING, "Can't parse version number '", cfg["binversion"], "'")
  end

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configfile = opts.prefix .. configfile
  end

  fh, msg = io.open(configfile .. ".tmp", "w")
  if fh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", configfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. configfile .. ".tmp' for writing: " .. msg
  end

  -- adjust owner & permissions before writing any content
  i, msg = LC.fs.setperm(configfile .. ".tmp", '0644', cfg.cfgfileowner, cfg.cfgfilegroup)
  if i==nil then
    LC.log.print(LC.log.WARNING, "Error while updating file permissions for '", configfile, "': ", msg)
  end

  -- write header
  LC.liveconfig.writeHeader(fh)

  -- write config...
  fh:write([[

# This is the main configuration file for the ISC BIND nameserver. This file
# is maintained by LiveConfig - do not modify anything here!

# ----------------------------------------------------------------------------

# Only these hosts are allowed to request zone transfers:
acl "xfer" {
    none;
};

# Only these IPs/networks are allowed to use this name server for recursive
# queries:
acl "trusted" {
    127.0.0.1/8;
    ::1/128;
};

# General configuration options:
options {

]])

  -- write global options
  fh:write("    version         \"yes\";\n")
  fh:write("    directory       \"" .. cfg.cachepath .. "\";\n")
  fh:write("    statistics-file \"" .. cfg.statsfile .. "\";\n")

  -- write distribution-specific options
  if LC.distribution.family == "Gentoo" or LC.distribution.family == "RedHat" then
    -- write 'pid-file' option
    fh:write("    pid-file        \"/var/run/named/named.pid\";\n")
  end

  -- insert list of IP addresses to listen at
  -- always listen on local interfaces:
  local interfaces_v4 = "127.0.0.1; "
  local interfaces_v6 = "::1; "
  for i=1, #opts.interfaces do
    if string.find(opts.interfaces[i], ":") then
      -- IPv6 address
      interfaces_v6 = interfaces_v6 .. opts.interfaces[i] .. "; "
    else
      -- IPv4 address
      interfaces_v4 = interfaces_v4 .. opts.interfaces[i] .. "; "
    end
  end
  if interfaces_v6 ~= "" then
    -- IPv6 addresses are ignored if no IPv6 interfaces are configured on this host:
    fh:write("    listen-on-v6    { ", interfaces_v6, "};\n")
  end
  if interfaces_v4 ~= "" then
    fh:write("    listen-on       { ", interfaces_v4, "};\n")
  end

  fh:write([[

    allow-query {
        any;
    };

    allow-transfer {
        # Zone transfers are denied by default.
        none;
    };

    allow-recursion {
        trusted;
    };

]])

  if v_major > 9 or (v_major == 9 and v_minor >= 4) then
    -- "allow-update" as global option supported from BIND 9.4.x
    fh:write( "    allow-update {\n",
              "        # Updates are denied by default.\n",
              "        none;\n",
              "    };\n\n")

    -- "allow-query-cache" as global option supported from BIND 9.4.x
    fh:write( "    allow-query-cache {\n",
              "        trusted;\n",
              "    };\n\n")

  end

  fh:write("};\n\n")

  -- include LiveConfig's zone list and TSIG keys:
  fh:write("include \"", configpath, "/keys.liveconfig\";\n")
  fh:write("include \"", configpath, "/zones.liveconfig\";\n")
  fh:write("\n")

  if not LC.fs.is_file(configpath .. "/keys.liveconfig") then
    -- create empty "keys" file
    local f = io.open(configpath .. "/keys.liveconfig", "w")
    LC.fs.setperm(configpath .. "/keys.liveconfig", '0640', cfg.cfgfileowner, cfg.cfgfilegroup)
    f:close()
  end

  if not LC.fs.is_file(configpath .. "/zones.liveconfig") then
    -- create empty "zones" file
    local f = io.open(configpath .. "/zones.liveconfig", "w")
    LC.fs.setperm(configpath .. "/zones.liveconfig", '0640', cfg.cfgfileowner, cfg.cfgfilegroup)
    f:close()
  end

  -- additional distribution-specific options
  if LC.distribution.family == "Gentoo" then
    fh:write([[
include "/etc/bind/rndc.key";
controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1/32; ::1/128; } keys { "rndc-key"; };
};

zone "." in {
    type hint;
    file "/var/bind/root.cache";
};

zone "localhost" IN {
    type master;
    file "pri/localhost.zone";
    notify no;
};

zone "127.in-addr.arpa" IN {
    type master;
    file "pri/127.zone";
    notify no;
};

]])
  end

  -- write footer
  LC.liveconfig.writeFooter(fh)

  fh:close()

  -- rename config file
  LC.fs.rename(configfile .. ".tmp", configfile)

  -- check chroot configuration (eg. OpenSUSE!)
  if cfg.chrootpath ~= nil and LC.fs.is_file(cfg.chrootpath .. cfg.configfile) then
    LC.fs.copy(cfg.configfile, cfg.chrootpath .. cfg.configfile)
  end

  -- trigger server restart ('reconfig' is not sufficient: if running as unauthorized user 'bind' it can't open port 53!)
  LC.timeout.set('bind.restart', 10, 60)

  return true
end

-- ---------------------------------------------------------------------------
-- updateKeys(cfg, keys)
--
-- update TSIG keys
-- ---------------------------------------------------------------------------
function updateKeys(cfg, data)
  local keyfile = cfg.configpath .. "/keys.liveconfig"

  local fh, msg = io.open(keyfile .. ".tmp", "w")
  if fh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", keyfile, ".tmp' for writing: ", msg)
    return false, "Can't open '" .. keyfile .. ".tmp' for writing: " .. msg
  end

  i, msg = LC.fs.setperm(keyfile .. ".tmp", '0640', cfg.cfgfileowner, cfg.cfgfilegroup)
  if i==nil then
    LC.log.print(LC.log.WARNING, "Error while updating file permissions for '", keyfile, ".tmp': ", msg)
  end

  LC.liveconfig.writeHeader(fh)
  fh:write("# Created at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
  fh:write("\n")

  local keyname
  for keyname in pairs(data.keys) do
    fh:write("key \"", keyname, "\" {\n")
    fh:write("\talgorithm hmac-md5;\n")
    fh:write("\tsecret \"", data.keys[keyname].secret, "\";\n")
    fh:write("};\n\n")
  end

  -- configure which TSIG keys have to be used for which master server:
  if data.servers ~= nil then
    local srv
    for srv in pairs(data.servers) do
      fh:write("server ", srv, " {\n")
      fh:write("\tkeys { ", data.servers[srv], ".; };\n")
      fh:write("};\n\n")
    end
  end

  fh:write("# <EOF>\n")
  fh:close()

  -- rename file
  LC.fs.rename(keyfile .. ".tmp", keyfile)

  -- check chroot configuration (eg. OpenSUSE!)
  if cfg.chrootpath ~= nil and LC.fs.is_file(cfg.chrootpath .. keyfile) then
    LC.fs.copy(keyfile, cfg.chrootpath .. keyfile)
  end

  return true
end

-- ---------------------------------------------------------------------------
-- addZone(cfg, zone)
--
-- Add zone
-- ---------------------------------------------------------------------------
function addZone(cfg, data)
  LC.log.print(LC.log.DEBUG, "addZone()")

  if data.type == "master" then

    -- check if zone path exists
    if not LC.fs.is_dir(cfg.zonepath) then
      LC.fs.mkdir_rec(cfg.zonepath)
      LC.fs.setperm(zonefile, "0770", cfg.cfgfileowner, cfg.cfgfilegroup)
    end

    -- add zone file
    local zonefile = cfg.zonepath .. "/" .. data.zone .. ".db"

    local fh, msg = io.open(zonefile .. ".tmp", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", zonefile, ".tmp' for writing: ", msg)
      return false, "Can't open '" .. zonefile .. ".tmp' for writing: " .. msg
    end

    -- adjust permissions
    LC.fs.setperm(zonefile .. ".tmp", '0640', cfg.cfgfileowner, cfg.cfgfilegroup)

    LC.liveconfig.writeHeader(fh, ";")
    fh:write("; Created at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
    fh:write("\n")

    fh:write("$ORIGIN .\n")

    -- write SOA
    local mail_user = string.match(data.email, "^(.*)@")
    local mail_domain = string.match(data.email, "@(.*)$")
    local lastOrigin = ''
    fh:write(data.zone, "\t86400\tIN SOA\t", data.master, ". ", string.gsub(mail_user, '%.', '\\.'), '.', mail_domain, ". (\n")
    fh:write("\t\t\t\t", data.serial, "\t; serial\n")
    fh:write("\t\t\t\t", data.refresh, "\t; refresh\n")
    fh:write("\t\t\t\t", data.retry, "\t; retry\n")
    fh:write("\t\t\t\t", data.expire, "\t; expire\n")
    fh:write("\t\t\t\t", data.minttl, "\t; minimum (neg. TTL)\n")
    fh:write("\t\t\t\t)\n")

    if data.rr~=nil then
      local key, rrs, i
      local st = {}     -- table for sorted indexes
      for key in pairs(data.rr) do
        table.insert(st, key)
      end
      table.sort(st)
--      for key, rrs in pairs(data.rr) do
      for key in pairs(st) do
        if lastOrigin ~= st[key] then
          if lastOrigin == '' then
            fh:write("$ORIGIN ", data.zone, ".\n")
          end
          lastOrigin = st[key]
        end
        rrs = data.rr[st[key]]
        for i in pairs(rrs) do
          local ttl = data.rrttl
          if rrs[i].ttl then ttl = rrs[i].ttl end
          fh:write(st[key], "\t\t", ttl, "\tIN ", LC.dns.NS_TYPES[rrs[i].type], "\t")
          if (rrs[i].prio ~= nil) then fh:write(rrs[i].prio, " ") end
          fh:write(rrs[i].data)
          if rrs[i].type == LC.dns.NS_T_NS or rrs[i].type == LC.dns.NS_T_MX then
            fh:write(".")
          end
          fh:write("\n")
        end
      end
    end

    fh:write("; <EOF>\n")
    fh:close()

    -- rename file
    LC.fs.rename(zonefile .. ".tmp", zonefile)

  end -- master zone file

  -- add to zone list
  return updateZone(cfg, data)

end

-- ---------------------------------------------------------------------------
-- updateZone(cfg, zone)
--
-- Update zone configuration (IPs/TSIG keys of other name servers)
-- ---------------------------------------------------------------------------
function updateZone(cfg, data)
  LC.log.print(LC.log.DEBUG, "updateZone()")

  -- update zone list
  local fhr, fhw
  -- open input file
  if LC.fs.is_file(cfg.zonefile) then
    fhr, msg = io.open(cfg.zonefile, "r")
    if fhr == nil then
      LC.log.print(LC.log.ERR, "Can't open '", cfg.zonefile, "' for reading: ", msg)
      return false, "Can't open '", cfg.zonefile, "' for reading: " .. msg
    end
  end

  -- open temporary output file
  fhw, msg = io.open(cfg.zonefile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", cfg.zonefile, ".tmp' for writing: ", msg)
    if fhr ~= nil then fhr:close() end
    return false, "Can't open '", cfg.zonefile, ".tmp' for writing: " .. msg
  end

  -- adjust permissions
  LC.fs.setperm(cfg.zonefile .. ".tmp", '0640', cfg.cfgfileowner, cfg.cfgfilegroup)

  -- write header
  LC.liveconfig.writeHeader(fhw)
  fhw:write("# DO NOT MODIFY - ANY CHANGES WILL BE OVERWRITTEN!\n")
  fhw:write("# Last updated at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
  fhw:write("# ----------------------------------------------------------------------------\n\n")

  -- copy line by line (except the entry to be updated)
  local line
  local found = false
  local empty = true

  while fhr ~= nil do
    line = fhr:read()
    if line == nil then break end

    if line == "" then
      -- dont copy multiple empty lines
      if empty then
        line = nil
      else
        empty = true
      end
    elseif string.find(line, "^#") then
      -- don't copy comment lines
      line = nil
    else
      empty = false
    end

    if line ~= nil then
      if not found then
        local z = string.match(line, "^zone \"([^\"]+)\"")
        -- check if there's an add/update for this zone
        if z ~= nil and z == data.zone then
          -- found entry!
          found = true
        end
      else
        if string.find(line, "^};") then
          -- end of found section
          found = false
          line = nil
        end
      end
      if not found and line ~= nil then
        fhw:write(line, "\n")
      end
    end
  end

  -- add new/updated zone
  fhw:write("zone \"", data.zone, "\" {\n")
  if data.type == "master" then
    -- MASTER
    fhw:write("\ttype master;\n")
    fhw:write("\tfile \"", cfg.zonepath, "/", data.zone, ".db\";\n")
    fhw:write("\tupdate-policy { grant LiveConfig. subdomain ", data.zone, ". ANY; };\n")
    -- allow-transfer
    if data.transfer ~= nil then
      fhw:write("\tallow-transfer {")
      if data.transfer.ips ~= nil then
        for i in pairs(data.transfer.ips) do
          fhw:write(" ", data.transfer.ips[i], ";")
        end
      end
      if data.transfer.keys ~= nil then
        for i in pairs(data.transfer.keys) do
          fhw:write(" key ", data.transfer.keys[i], ".;")
        end
      end
      fhw:write(" };\n")
    end
  elseif data.type == "slave" then
    -- MASTER
    fhw:write("\ttype slave;\n")
    fhw:write("\tfile \"", data.zone, ".db\";\n")
    fhw:write("\tmasters {")
    for i in pairs(data.masters) do
      fhw:write(" ", data.masters[i], ";")
    end
    fhw:write(" };\n")
  end

  fhw:write("};\n")

  -- close (temporary) file
  LC.liveconfig.writeFooter(fhw)
  fhw:close()

  -- close input file
  if fhr ~= nil then
    fhr:close()
  end

  -- rename file
  LC.fs.rename(cfg.zonefile .. ".tmp", cfg.zonefile)

  -- check chroot configuration (eg. OpenSUSE!)
  if cfg.chrootpath ~= nil and LC.fs.is_file(cfg.chrootpath .. cfg.zonefile) then
    LC.fs.copy(cfg.zonefile, cfg.chrootpath .. cfg.zonefile)
  end

  -- Reload configuration file and new zones only.
  LC.timeout.set('bind.reconfig', 10, 60)

  return true

end

-- ---------------------------------------------------------------------------
-- delZone(cfg, zone)
--
-- Delete zone
-- ---------------------------------------------------------------------------
function delZone(cfg, data)
  LC.log.print(LC.log.DEBUG, "delZone()")

  -- remove from zone list
  local fhr, fhw
  -- open input file
  if LC.fs.is_file(cfg.zonefile) then
    fhr, msg = io.open(cfg.zonefile, "r")
    if fhr == nil then
      LC.log.print(LC.log.ERR, "Can't open '", cfg.zonefile, "' for reading: ", msg)
      return false, "Can't open '", cfg.zonefile, "' for reading: " .. msg
    end
  end

  -- open temporary output file
  fhw, msg = io.open(cfg.zonefile .. ".tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", cfg.zonefile, ".tmp' for writing: ", msg)
    if fhr ~= nil then fhr:close() end
    return false, "Can't open '", cfg.zonefile, ".tmp' for writing: " .. msg
  end

  -- adjust permissions
  LC.fs.setperm(cfg.zonefile .. ".tmp", '0640', cfg.cfgfileowner, cfg.cfgfilegroup)

  -- write header
  LC.liveconfig.writeHeader(fhw)
  fhw:write("# DO NOT MODIFY - ANY CHANGES WILL BE OVERWRITTEN!\n")
  fhw:write("# Last updated at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
  fhw:write("# ----------------------------------------------------------------------------\n\n")

  -- copy line by line (except the entry to be removed)
  local line
  local found = false
  local empty = true

  while fhr ~= nil do
    line = fhr:read()
    if line == nil then break end

    if line == "" then
      -- dont copy multiple empty lines
      if empty then
        line = nil
      else
        empty = true
      end
    elseif string.find(line, "^#") then
      -- don't copy comment lines
      line = nil
    else
      empty = false
    end

    if line ~= nil then
      if not found then
        local z = string.match(line, "^zone \"([^\"]+)\"")
        -- check if there's an add/update for this zone
        if z ~= nil and z == data.zone then
          -- found entry!
          found = true
        end
      else
        if string.find(line, "^};") then
          -- end of found section
          found = false
          line = nil
        end
      end
      if not found and line ~= nil then
        fhw:write(line, "\n")
      end
    end
  end

  -- close (temporary) file
  LC.liveconfig.writeFooter(fhw)
  fhw:close()

  -- close input file
  if fhr ~= nil then
    fhr:close()
  end

  -- rename file
  LC.fs.rename(cfg.zonefile .. ".tmp", cfg.zonefile)

  -- check chroot configuration (eg. OpenSUSE!)
  if cfg.chrootpath ~= nil and LC.fs.is_file(cfg.chrootpath .. cfg.zonefile) then
    LC.fs.copy(cfg.zonefile, cfg.chrootpath .. cfg.zonefile)
  end

  -- Reload configuration file and new zones only.
  LC.timeout.set('bind.reconfig', 10, 60)


  local zonefile = cfg.zonepath .. "/" .. data.zone .. ".db"

  -- delete zone file
  os.remove(zonefile)

  -- delete journal file (if existing)
  os.remove(zonefile .. ".jnl")

  return true

end

-- ---------------------------------------------------------------------------
-- reconfig()
--
-- Reload configuration and new zones only
-- ---------------------------------------------------------------------------
function reconfig()
  LC.log.print(LC.log.DEBUG, "bind.reconfig() called")
  -- get configuration
  local cfg = LC.dns.getConfig('bind')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "bind.reconfig(): no configuration for 'bind' available!?")
    return
  end
  -- get reconfig command
  if cfg.reconfig_cmd == nil then
    LC.log.print(LC.log.ERR, "bind.reconfig(): no reconfig command for 'bind' available!?")
    return
  end

  -- reload service
  os.execute(cfg.reconfig_cmd)

end

-- ---------------------------------------------------------------------------
-- restart()
--
-- Restart name server
-- ---------------------------------------------------------------------------
function restart()
  LC.log.print(LC.log.DEBUG, "bind.restart() called")
  -- get configuration
  local cfg = LC.dns.getConfig('bind')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "bind.restart(): no configuration for 'bind' available!?")
    return
  end
  -- get reconfig command
  if cfg.restart_cmd == nil then
    LC.log.print(LC.log.ERR, "bind.restart(): no reconfig command for 'bind' available!?")
    return
  end

  -- reload service
  os.execute(cfg.restart_cmd)

end

-- <EOF>----------------------------------------------------------------------
