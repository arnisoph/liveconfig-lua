--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2014 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/web.lua
-- Web server management
--
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local LCS = LCS
local type = type
local io = io
local os = os
local string = string
local require = require
local pairs = pairs
local tonumber = tonumber

-- Module declaration
module("web")

-- Exported functions
-- getWebRoot()
-- load()
-- detect()
-- getConfig()
-- install()
-- uninstall()
-- configure()
-- addAccount()
-- deleteAccount()
-- updateAccount()
-- configureVHost()
-- updatePasswd()
-- addPHP()
-- getPHP()

-- Exported variables
-- HTDOCS_PATH

-- define the path name for webspace (/var/www/<SUBSCRIPTION>/<HTDOCS_PATH/)
if HTDOCS_PATH == nil then
  HTDOCS_PATH = 'htdocs'
end

-- ---------------------------------------------------------------------------

-- module variables
local modlist = { }

-- array to manage additional PHP versions
local phplist = { }

-- ---------------------------------------------------------------------------
-- getWebRoot()
-- Return web root directory (without trailing slash!!!)
-- ---------------------------------------------------------------------------
function getWebRoot()
  if LC.distribution.family == "Debian" then
    return "/var/www"
  elseif LC.distribution.family == "SunOS" then
    return "/var/apache2/2.2/htdocs"
  elseif LC.distribution.family == "RedHat" then
    return "/var/www"
  elseif LC.distribution.family == "SUSE" then
    return "/srv/www"
  elseif LC.distribution.family == "BSD" then
    return "/usr/local/www/apache22/data"
  elseif LC.distribution.family == "Gentoo" then
    return "/var/www"
  end

  -- return default path
  return "/var/www"
end

-- ---------------------------------------------------------------------------
-- load(modname)
--
-- Load "driver" module for a specific web server
-- ---------------------------------------------------------------------------
function load(mod)
  modlist[mod] = require(mod)
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect installed web server packages
-- ---------------------------------------------------------------------------
function detect()
  local data = {}
  local mod

  -- check if web server software was already detected; avoid double-detection
  -- also across multiple threads
  LC.mutex.lock("web.detect")

  if LCS.web ~= nil then
    if LCS.web.data ~= nil then
      -- web server software already detected; load values from global LCS storage
      LC.mutex.unlock("web.detect")
      return LCS.web.data
    end
  end

  -- run detection handler for all installed driver modules
  LC.log.print(LC.log.DEBUG, "running web.detect()")
  for mod in pairs(modlist) do
    local m = modlist[mod].detect()
    if m then
      data[#data+1] = m
      -- now check for configuration revision (if already managed by LiveConfig)
      if m.statusfile and LC.fs.is_file(m.statusfile) then
        local r = LC.liveconfig.readStatus(m.statusfile)
        if r and r.revision then
          -- this module is in use
          data[#data].revision = r.revision
          -- call init function (if existing)
          if modlist[mod].init then
            modlist[mod].init()
          end
        end
      end
    end
  end

  LCS.web = {
    generated = true,
    data      = data    -- LCS.web.data = (local)data
  }

  -- detect PHP version
  local php
  if LC.fs.is_file("/usr/bin/php-cgi") then
    php = "/usr/bin/php-cgi"
  elseif LC.fs.is_file("/usr/bin/php") then
    php = "/usr/bin/php"
  end

  --TODO: some users may want to use the default bin, provide variable like
  -- web.use_default_php = False to optionally disable it
  --if php ~= nil then
  --  addPHP(nil, php)
  --end

  LCS.web.phpVersions = phplist

  LC.mutex.unlock("web.detect")

  return data
end

-- ---------------------------------------------------------------------------
-- getConfig()
--
-- Return configuration table for specified web server
-- (eg. "apache" or "lighttpd")
-- ---------------------------------------------------------------------------
function getConfig(name)
  local w = detect()
  local i
  for i in pairs(w) do
    if w[i]['type'] == name then
      return w[i]
    end
  end
end

-- ---------------------------------------------------------------------------
-- install()
--
-- Start management of web server
-- ---------------------------------------------------------------------------
function install(config, opts)
  if config == nil or config.type == nil then
    LC.log.print(LC.log.ERR, "web.install(): no configuration submitted")
    return false, "web.install(): no configuration submitted"
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for web server '", config.type, "' found")
    return false, "No module for web server '" .. config.type .. "' found"
  end

  -- adjust permissions of web root directory
  LC.fs.setperm(getWebRoot(), 751, "root", "root")

  -- run install() function from web server module
  return modlist[config.type].install(config, opts)

end

-- ---------------------------------------------------------------------------
-- uninstall()
--
-- Stop management of web server
-- ---------------------------------------------------------------------------
function uninstall(config, opts)
  if config == nil or config.type == nil then
    return false
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for web server '", config.type, "' found")
    return false
  end

  -- run uninstall() function from web server module
  return modlist[config.type].uninstall(config, opts)
end

-- ---------------------------------------------------------------------------
-- configure()
--
-- Configure web server
-- ---------------------------------------------------------------------------
function configure(opts)

  LC.log.print(LC.log.DEBUG, "LC.web.configure()")

  local res, msg
  -- check options
  if opts == nil or opts.server == nil then
    return false, "No web server specified"
  end

  -- get configuration
  local cfg = getConfig(opts.server)
  if cfg == nil then
    return false, "Web server '" .. opts.server .. "' not found"
  end

  local statusfile = cfg["statusfile"]
  if opts and opts.prefix then
    statusfile = opts.prefix .. statusfile
  end

  -- core configuration (LiveConfig) already installed?
  if not LC.fs.is_file(statusfile) then
    -- install LiveConfig configuration
    res, msg = modlist[cfg.type].install(cfg, opts)
    if res == false then
      return false, msg
    end
    local r = LC.liveconfig.readStatus(statusfile)
    if r and r.revision then
      -- managed sucessfully. :)
      cfg.revision = r.revision
    end
  end

  -- update core configuration & restart service
  res, msg = modlist[cfg.type].configure(cfg, opts)
  if not res then
    return false, msg
  end

  return true
end

-- ---------------------------------------------------------------------------
local function getWebUser()
  -- get group name under which web server runs
  local wwwuser  = "www-data"
  local wwwgroup = "www-data"
  if LC.distribution.family == "Gentoo" or LC.distribution.family == "RedHat" then
    wwwuser  = "apache"
    wwwgroup = "apache"
  elseif LC.distribution.family == "SUSE" then
    wwwuser  = "wwwrun"
    wwwgroup = "www"
  elseif LC.distribution.family == "BSD" then
    wwwuser  = "www"
    wwwgroup = "www"
  end
  return wwwuser, wwwgroup
end

-- ---------------------------------------------------------------------------
-- addAccount()
--
-- Add a new webspace account
-- ---------------------------------------------------------------------------
function addAccount(name, quota, shell, password)

  -- get group name under which web server runs
  local wwwuser, wwwgroup = getWebUser()

  -- build home directory name
  local home = getWebRoot() .. "/" .. name

  -- create group
  if not LC.sys.group_exists(name) then
    LC.log.print(LC.log.DEBUG, "Adding group '" .. name .. "'")
    if LC.users.addGroup(name) == false then
      -- group creation failed
      return false
    end
  end

  -- create user
  if not LC.sys.user_exists(name) then
    LC.log.print(LC.log.DEBUG, "Adding user '" .. name .. "'")
    if shell ~= "sh" and shell ~= "scponly" then shell="nologin" end
    if not LC.users.addUser(name, name, home, shell) then
      -- user creation failed
      return false
    end
  end

  -- set new password (if given)
  if password ~= nil then
    LC.users.chPasswd(name, password)
  end

  LC.log.print(LC.log.DEBUG, "home: ", home)

  -- create home directory (if not existing)
  if not LC.fs.is_dir(home) then
    LC.log.print(LC.log.DEBUG, "creating home: ", home)
    LC.fs.mkdir_rec(home)

    -- adjust SElinux permission type
    if LC.distribution.family == "RedHat" then
      os.execute("chcon -t user_home_dir_t \"" .. home .. "\"")
    end
  end

  -- adjust permissions of home directory
  -- the home dir itself is owned by root:root, so the customer is *not*
  -- allowed to create or modify any files here.
  LC.fs.setperm(home, 755, "root", "root")

  -- create 'htdocs' directory (if not existing), and adjust permissions
  if not LC.fs.is_dir(home .. "/" .. HTDOCS_PATH) then
    LC.fs.mkdir(home .. "/" .. HTDOCS_PATH)

    -- adjust SElinux permission type
    if LC.distribution.family == "RedHat" then
      os.execute("chcon -t user_home_t \"" .. home .. "/" .. HTDOCS_PATH .. "\"")
    end
  end
  LC.fs.setperm(home .. "/" .. HTDOCS_PATH, 750, name, wwwgroup)

  if LC.distribution.family == "RedHat" then
    -- only on RedHat/CentOS: prepare "apps" directory and adjust SELinux permissions!
    if not LC.fs.is_dir(home .. "/apps") then
      LC.fs.mkdir(home .. "/apps")
      LC.fs.setperm(home .. "/apps", 750, name, wwwgroup)
      os.execute("chcon -t user_home_t \"" .. home .. "/apps\"")
    end
  end

  -- create 'logs' directory (if not existing), and adjust permissions
  if not LC.fs.is_dir(home .. "/logs") then
    LC.fs.mkdir(home .. "/logs")
  end
  LC.fs.setperm(home .. "/logs", 750, wwwuser, name)
  -- adjust SElinux permission type
  if LC.distribution.family == "RedHat" then
    os.execute("chcon -t httpd_log_t \"" .. home .. "/logs\"")
  end

  -- create 'logs/priv' directory (if not existing), and adjust permissions
  if not LC.fs.is_dir(home .. "/logs/priv") then
    LC.fs.mkdir(home .. "/logs/priv")
  end
  LC.fs.setperm(home .. "/logs/priv", 770, wwwuser, name)
  -- adjust SElinux permission type
  if LC.distribution.family == "RedHat" then
    os.execute("chcon -t httpd_log_t \"" .. home .. "/logs/priv\"")
  end

  -- create 'priv' directory (if not existing), and adjust permissions
  if not LC.fs.is_dir(home .. "/priv") then
    LC.fs.mkdir(home .. "/priv")
  end
  LC.fs.setperm(home .. "/priv", 750, name, name)

  -- create 'tmp' directory (if not existing), and adjust permissions
  if not LC.fs.is_dir(home .. "/tmp") then
    LC.fs.mkdir(home .. "/tmp")
  end
  LC.fs.setperm(home .. "/tmp", 770, name, wwwgroup)

  -- set quota (if defined)
  if quota ~= nil and quota > 0 then
    LC.fs.setGroupQuota(name, home, quota)
  end

  return true, home

end

-- ---------------------------------------------------------------------------
-- deleteAccount()
--
-- Delete a webspace account
-- ---------------------------------------------------------------------------
function deleteAccount(name)

  LC.mutex.lock("web.configure")

  LC.log.print(LC.log.DEBUG, "LC.web.deleteAccount()")

  -- remove all configuration files
  local i
  for i in pairs(LCS.web.data) do
    local cfg = LCS.web.data[i]
    if cfg.revision ~= nil then
      modlist[cfg.type].deleteAccount(cfg, name)
    end -- if cfg.revision...
  end

  LC.mutex.unlock("web.configure")

  -- convert to lowercase (user/group/path are all lowercase)
  name = name:lower()

  -- build home directory name
  local home = getWebRoot() .. "/" .. name

  -- remove user's home directory
  if home ~= nil and LC.fs.is_dir(home) and home ~= "/" and name ~= "" then
    LC.log.print(LC.log.INFO, "Deleting directory '" .. home .. "' ...")

    -- remove "immutable" flags:
    LC.exec("chattr -f -i " .. home .. "/conf/*/php.ini")
    LC.exec("chattr -f -i " .. home .. "/conf/*/php-fcgi-starter")

    LC.exec("rm -rf " .. home)
    LC.log.print(LC.log.INFO, "Deleting directory '" .. home .. "': DONE")
  end

  -- delete user
  if LC.sys.user_exists(name) then
    LC.log.print(LC.log.DEBUG, "Deleting user '" .. name .. "'")
    if not LC.users.delUser(name) then
      -- deleting the user failed
      return false
    end
  end

  -- delete group
  if LC.sys.group_exists(name) then
    LC.log.print(LC.log.DEBUG, "Deleting group '" .. name .. "'")
    if not LC.users.delGroup(name) then
      -- deleting the group failed
      return false
    end
  end

  return true

end

-- ---------------------------------------------------------------------------
-- updateAccount()
--
-- Update an existing webspace account
-- ---------------------------------------------------------------------------
function updateAccount(name, data)
  local ret = true

  if data.password ~= nil then
    ret = LC.users.chPasswd(name, data.password)
  end

  if data.shell ~= nil then
    ret = LC.users.chShell(name, data.shell)
  end

  if data.quota ~= nil then
    -- set quota (if defined)
    local home = getWebRoot() .. "/" .. name
    LC.fs.setGroupQuota(name, home, data.quota)
  end

  return ret

end

-- ---------------------------------------------------------------------------
-- updateLogrotate()
--
-- Update logrotate configuration in /etc/logrotate.d/liveconfig
-- ---------------------------------------------------------------------------
local function updateLogrotate(opts)
  if not LC.fs.is_dir("/etc/logrotate.d") then
    -- obviously no logrotate installed - abort...
    return
  end

  local fhr, fhw, msg
  -- open input file
  if LC.fs.is_file("/etc/logrotate.d/liveconfig") then
    fhr, msg = io.open("/etc/logrotate.d/liveconfig", "r")
    if fhr == nil then
      LC.log.print(LC.log.ERR, "Can't open '/etc/logrotate.d/liveconfig' for reading: ", msg)
      return false, "Can't open '/etc/logrotate.d/liveconfig' for reading: " .. msg
    end
  end

  -- open temporary output file
  fhw, msg = io.open("/etc/logrotate.d/liveconfig.tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '/etc/logrotate.d/liveconfig.tmp' for writing: ", msg)
    if fhr ~= nil then fhr:close() end
    return false, "Can't open '/etc/logrotate.d/liveconfig.tmp' for writing: " .. msg
  end

  -- write header
  LC.liveconfig.writeHeader(fhw)
  fhw:write("# DO NOT MODIFY - ANY CHANGES WILL BE OVERWRITTEN!\n")
  fhw:write("# Last updated at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
  fhw:write("# ----------------------------------------------------------------------------\n\n")

  -- copy line by line (except the entry to be updated)
  local line
  local found = false
  local empty = true
  local search = "^" .. opts.path .. "/logs/access.log {"
  search = string.gsub(search, "%%", "%%%%")
  search = string.gsub(search, "%.", "%%.")
  search = string.gsub(search, "%-", "%%-")
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
        if string.find(line, search) then
          -- found entry!
          found = true
        else
          local v = string.match(line, "^(/.*)/logs/access.log {")
          if v and not LC.fs.is_dir(v) then
            -- found another logrotate entry; remove if customer directory doesn't exist any more:
            LC.log.print(LC.log.INFO, "Removing orphaned entry '", v, "/logs/access.log' from logrotate configuration")
            found = true
          end
        end
      else
        if string.find(line, "^}") then
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

  -- add new/updated entry
  fhw:write(opts.path .. "/logs/access.log {\n")
  if opts.logrotate ~= nil then
    if opts.logrotate.size ~= nil then
      fhw:write("    size ", opts.logrotate.size, "M\n")
    elseif opts.logrotate.interval == 1 then
      fhw:write("    daily\n")
    elseif opts.logrotate.interval == 2 then
      fhw:write("    weekly\n")
    else
      fhw:write("    monthly\n")
    end
    if opts.logrotate.compress then
      fhw:write("    compress\n    delaycompress\n")
    else
      fhw:write("    nocompress\n")
    end
    if opts.logrotate.keep ~= nil then
      fhw:write("    rotate ", opts.logrotate.keep, "\n")
    elseif opts.logrotate.maxage ~= nil then
      fhw:write("    maxage ", opts.logrotate.maxage, "\n")
    else
      fhw:write("    maxage 100\n")
    end
  else
    -- use default values
    fhw:write("    monthly\n",
              "    compress\n",
              "    delaycompress\n")
  end
  fhw:write([[
    missingok
    notifempty
    sharedscripts
    postrotate
      /usr/bin/killall -HUP lclogsplit
    endscript
}

]])

  -- close (temporary) config file
  LC.liveconfig.writeFooter(fhw)
  fhw:close()

  -- close input file
  if fhr ~= nil then
    fhr:close()
  end

  -- rename map file
  LC.fs.rename("/etc/logrotate.d/liveconfig.tmp", "/etc/logrotate.d/liveconfig")

end

-- ---------------------------------------------------------------------------
-- updatePhpIni()
--
-- Create/update customized php.ini files per subscription:
-- ---------------------------------------------------------------------------
local function updatePhpIni(opts)
  local inputfile

  -- get group name under which web server runs
  local wwwuser, wwwgroup = getWebUser()

  -- iterate through all detected PHP versions
  local phpidx
  for phpidx in pairs(LCS.web.phpVersions) do
    local php = LCS.web.phpVersions[phpidx]
    local inputfile = php["ini"]
    local code = php["code"]
    local pv = php["versionInt"]
    local i, fhr, fhw, msg

    -- create destination path (if not existing)
    if not LC.fs.is_dir(opts.path .. "/conf") then
      LC.fs.mkdir(opts.path .. "/conf")
      LC.fs.setperm(opts.path .. "/conf", 750, wwwuser, opts.group)
    end
    if not LC.fs.is_dir(opts.path .. "/conf/" .. code) then
      LC.fs.mkdir(opts.path .. "/conf/" .. code)
      LC.fs.setperm(opts.path .. "/conf/" .. code, 555, opts.user, opts.group)
    end

    -- open temporary output file
    fhw, msg = io.open(opts.path .. "/conf/" .. code .. "/php.ini.tmp", "w")
    if fhw == nil then
      LC.log.print(LC.log.ERR, "Can't open '", opts.path .. "/conf/" .. code .. "/php.ini.tmp' for writing: ", msg)
      return false, "Can't open '", opts.path .. "/conf/" .. code .. "/php.ini.tmp' for writing: " .. msg
    end

    LC.liveconfig.writeHeader(fhw, ';')
    fhw:write("; DO NOT MODIFY - ANY CHANGES WILL BE OVERWRITTEN!\n")
    fhw:write("; Last updated at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
    fhw:write("; ----------------------------------------------------------------------------\n\n")

    -- replacement table with custom php.ini settings:
    local replace = {
      ["php"] = { }
    }
    if opts.phpini ~= nil then
      -- load php.ini settings into replacement table
      for i in pairs(opts.phpini) do
        -- look for ad-hoc replacements:
        local value = opts.phpini[i].value
        value = string.gsub(value, "%%HOME%%", opts.path)
        local v_min = opts.phpini[i].min  -- minimum supported PHP version (as integer)
        local v_max = opts.phpini[i].max  -- supported up to this PHP version (not included)
        if pv == nil or ((v_min == nil or pv >= v_min) and (v_max == nil or pv < v_max)) then
          -- look for a dot in php.ini setting
          local dot = string.find(i, ".", 1, true)
          if dot ~= nil then
            -- use prefix as group name
            local group = string.sub(i, 1, dot-1)
            if replace[group] == nil then replace[group] = { } end
            replace[group][i] = value
          else
            -- use default group (PHP)
            replace["php"][i] = value
          end
        end -- PHP version check
      end
    end

    -- open default php.ini file
    fhr = nil
    if inputfile ~= nil then
      -- open input file
      fhr, msg = io.open(inputfile, "r")
      if fhr == nil then
        LC.log.print(LC.log.ERR, "Can't open '", inputfile, "' for reading: ", msg)
      end
    end

    if fhr ~= nil then
      -- parse & copy php.ini line by line
      local line
      local section
      while fhr ~= nil do
        line = fhr:read()
        if line == nil then break end

        if string.find(line, "^%s*;") or string.find(line, "^%s*$") then
          -- don't copy comment lines
          line = nil
        elseif string.find(line, "^%s*%[.*%]") then
          -- found (new) section
          -- write all not-yet written directives from previous section:
          if section ~= nil and replace[section] ~= nil then
            for i in pairs(replace[section]) do
              fhw:write(i, " = ", replace[section][i], "\n")
              replace[section][i] = nil
            end
            replace[section] = nil
          end

          -- now switch to new section
          section = string.lower(string.match(line, "^%s*%[(.*)%]"))
        else
          i = string.match(line, "^%s*(.-)%s*=")
          if i ~= nil and replace[section] ~= nil and replace[section][i] ~= nil then
            line = i .. " = " .. replace[section][i]
            replace[section][i] = nil
          end
        end

        if line ~= nil then
          -- replace placeholders:
          line = string.gsub(line, "##LC_WEBROOT##", opts.path)

          fhw:write(line, "\n")
        end
      end

      -- close input file
      if fhr ~= nil then
        fhr:close()
      end
    else
      fhw:write("; No default php.ini file available for ", php.bin, "\n\n")
    end

    -- append all sections not written yet:
    for section in pairs(replace) do
      fhw:write("[", section, "]\n")
      for i in pairs(replace[section]) do
        fhw:write(i, "=", replace[section][i], "\n")
      end
    end

    if opts.hasPHP == 1 then
      -- disable APC with suPHP
      fhw:write("; disabling APC with suPHP:\n")
      fhw:write("apc.enabled=off\n")
    end

    -- close (temporary) php.ini file
    LC.liveconfig.writeFooter(fhw, ';')
    fhw:close()

    -- adjust owner and permissions
    LC.fs.setperm(opts.path .. "/conf/" .. code .. "/php.ini.tmp", 644, "root", opts.group)
    -- adjust SElinux permission type
    if LC.distribution.family == "RedHat" then
      os.execute("chcon -t etc_t \"" .. opts.path .. "/conf/" .. code .. "/php.ini.tmp\"")
    end
    if LC.fs.is_file(opts.path .. "/conf/" .. code .. "/php.ini") then
      -- remove "immutable" flag:
      os.execute("chattr -i " .. opts.path .. "/conf/" .. code .. "/php.ini")
    end
    -- rename temporary php.ini file
    LC.fs.rename(opts.path .. "/conf/" .. code .. "/php.ini.tmp", opts.path .. "/conf/" .. code .. "/php.ini")
    -- set "immutable" flag:
    os.execute("chattr +i " .. opts.path .. "/conf/" .. code .. "/php.ini")

  end

end

-- ---------------------------------------------------------------------------
-- configureVHost()
--
-- Configure virtual host
-- ---------------------------------------------------------------------------
function configureVHost(opts)

  local res, msg

  LC.mutex.lock("web.configure")

  LC.log.print(LC.log.DEBUG, "LC.web.configureVHost()")

  -- check options
  if opts == nil or opts.name == nil then
    LC.mutex.unlock("web.configure")
    return false, "No or invalid options specified"
  end

  -- update individual php.ini files:
  if opts.hasPHP then
    updatePhpIni(opts)
  end

  -- iterate through all detected web servers:
  local i
  for i in pairs(LCS.web.data) do
    local cfg = LCS.web.data[i]
    -- server: cfg.type (eg. 'apache')
    -- update vHost configuration (only if service is managed by LiveConfig!)
    if cfg.revision ~= nil then
      res, msg = modlist[cfg.type].configureVHost(cfg, opts)
      if not res then
        LC.mutex.unlock("web.configure")
        return false, msg
      end
    end -- if cfg.revision...
  end

  -- update logrotate configuration:
  updateLogrotate(opts)

  -- check web statistics configuration
  if opts.webstats and opts.webstats.software > 0 then
    -- create stats path
    if not LC.fs.is_dir(opts.path .. "/stats") then
      local wwwuser, wwwgroup = getWebUser()
      LC.fs.mkdir(opts.path .. "/stats")
      LC.fs.setperm(opts.path .. "/stats", 750, wwwuser, opts.group)
    end

    -- install placeholder page (until stats have been generated)
    if not LC.fs.is_file(opts.path .. "/stats/index.html") then
      os.execute("cp /usr/share/liveconfig/html/no-stats.html " .. opts.path .. "/stats/index.html")
      LC.fs.setperm(opts.path .. "/stats/index.html", 644, "root", "root")
    end

    -- create rotated log file dummy
    if not LC.fs.is_file(opts.path .. "/logs/access.log.1") then
      local fh, msg = io.open(opts.path .. "/logs/access.log.1", "w")
      if fh == nil then
        LC.log.print(LC.log.ERR, "Can't open '", opts.path .. "/logs/access.log.1", "' for writing: ", msg)
      else
        fh:write("0.0.0.0 - - [01/Jan/2011:00:00:00 +0100] \"OPTIONS * HTTP/1.0\" 200 - \"-\" \"Dummy entry\" 0 0\n")
        fh:close()
        LC.fs.setperm(opts.path .. "/logs/access.log.1", 644, "root", "root")
      end
    end
  end

  -- ###TODO### move statistics configuration to own Lua file
  if LC.fs.is_file("/usr/bin/webalizer") then
    -- check if configuration has to be generated/deleted
    if opts.webstats and opts.webstats.software == 1 then
      -- most distributions don't install webalizer ready-to-use
      local filename
      if LC.distribution.family == "Debian" then
        filename = "/etc/webalizer/" .. opts.name .. ".conf"
      else
        if not LC.fs.is_dir("/etc/webalizer") then
          -- create directory
          LC.fs.mkdir("/etc/liveconfig/webalizer")
          LC.fs.setperm("/etc/liveconfig/webalizer", 755, "root", "root")
        end
        if not LC.fs.is_file("/etc/cron.daily/liveconfig.webalizer") then
          -- create webalizer cron job
          local fh, msg = io.open("/etc/cron.daily/liveconfig.webalizer", "w")
          if fh == nil then
            LC.log.print(LC.log.ERR, "Can't create '/etc/cron.daily/liveconfig.webalizer': ", msg)
          else
            fh:write("#!/bin/sh\n")
            LC.liveconfig.writeHeader(fh)
            fh:write("# Cron job for daily webalizer statistics\n")
            fh:write("# ----------------------------------------------------------------------------\n\n")
            fh:write([[
WEBALIZER=/usr/bin/webalizer
CONFDIR=/etc/liveconfig/webalizer

for i in ${CONFDIR}/*.conf; do

  # first try rotated log file:
  LOGFILE=`awk '$1 ~ /^LogFile$/ {print $2}' $i`;
  if [ -r "${LOGFILE}" ]; then
    ${WEBALIZER} -c ${i} -Q || continue;
  fi;

  # then check for non-rotated log file:
  NLOGFILE=`awk '$1 ~ /^LogFile$/ {gsub(/\.[0-9]+(\.gz)?/,""); print $2}' $i`;
  if [ "${LOGFILE}" != "${NLOGFILE}" -a -r "${NLOGFILE}" ]; then
    ${WEBALIZER} -c ${i} -Q ${NLOGFILE} || continue;
  fi;

done;

# done.
]])
            fh:close()
            LC.fs.setperm("/etc/cron.daily/liveconfig.webalizer", 755, "root", "root")
          end
        end
        filename = "/etc/liveconfig/webalizer/" .. opts.name .. ".conf"
      end

      -- create config file
      local tempfile = filename .. ".tmp"
      local fh, msg = io.open(tempfile, "w")
      if fh == nil then
        LC.log.print(LC.log.ERR, "Can't open '", tempfile, "' for writing: ", msg)
        LC.mutex.unlock("web.configure")
        return false, "Can't open '" .. tempfile .. "' for writing: " .. msg
      end
      LC.liveconfig.writeHeader(fh)
      fh:write("# Created at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
      fh:write("# ----------------------------------------------------------------------------\n\n")

      -- variable part:
      -- Webalizer is first run against a rotated log file, and then the current log file (to catch log rotation)
      fh:write("LogFile ", opts.path, "/logs/access.log.1\n")
      fh:write("OutputDir ", opts.path, "/stats\n")
      fh:write("HostName ", opts.name, "\n")

      -- static part:
      fh:write([[
ReportTitle Usage statistics for
Incremental     yes
PageType        htm*
PageType        php*
PageType        cgi
PageType        pl
PageType        shtml

HTMLHead  <style type="text/css">
HTMLHead    body, p, th, td, font { font-family:Arial, Helvetica, Sans-serif;
HTMLHead      font-size:12px; }
HTMLHead    body { background:url(images/bg.png) top left repeat-x #F0F0F0; }
HTMLHead    hr { border:0px; border-top:1px solid #999999;
HTMLHead      border-bottom:solid 1px #F0F0F0; }
HTMLHead    center > hr { visibility:hidden; }
HTMLHead    h2 { color:#222222; font-size:18px; font-weight:bold;
HTMLHead      text-shadow: 0px 1px 2px #999999; }
HTMLHead    tr > th[BGCOLOR="#C0C0C0"] { text-shadow: 1px 1px 0px #999999;
HTMLHead      font-size:13px; }
HTMLHead  </style>
HTMLBody <BODY BGCOLOR="#F0F0F0" TEXT="#000000" LINK="#0000FF" VLINK="#FF0000">
HTMLTail <img width="99" height="17" alt="LiveConfig" src="images/logo.png">

HideURL         *.gif
HideURL         *.GIF
HideURL         *.jpg
HideURL         *.JPG
HideURL         *.png
HideURL         *.PNG
HideURL         *.swf
HideURL         *.js
HideURL         *.css
HideURL         robots.txt
HideURL         favicon.ico

IgnoreSite      0.0.0.0

SearchEngine    yahoo.com       p=
SearchEngine    altavista.com   q=
SearchEngine    eureka.com      q=
SearchEngine    lycos.com       query=
SearchEngine    hotbot.com      MT=
SearchEngine    msn.com         MT=
SearchEngine    infoseek.com    qt=
SearchEngine    webcrawler      searchText=
SearchEngine    excite          search=
SearchEngine    netscape.com    search=
SearchEngine    mamma.com       query=
SearchEngine    alltheweb.com   query=
SearchEngine    northernlight.com  qr=
SearchEngine    sensis.com.au   find=
SearchEngine    www.google.     q=

]])

      LC.liveconfig.writeFooter(fh)
      fh:close()

      -- rename config file (atomic)
      LC.fs.rename(tempfile, filename)

    else
      -- delete webalizer config file (if existing)
      os.remove("/etc/webalizer/" .. opts.name .. ".conf")
    end
  end

  if LC.fs.is_dir("/etc/awstats") then
    -- check if configuration has to be generated/deleted
    if opts.webstats and opts.webstats.software == 2 then
      -- check if /etc/awstats/liveconfig exists
      if not LC.fs.is_dir("/etc/awstats/liveconfig") then
        LC.fs.mkdir("/etc/awstats/liveconfig")
      end

      -- check if default configuration already exists
      if not LC.fs.is_file("/etc/awstats/liveconfig/awstats.conf.liveconfig") then
        local filename = "/etc/awstats/liveconfig/awstats.conf.liveconfig"
        local fh, msg = io.open(filename, "w")
        if fh == nil then
          LC.log.print(LC.log.ERR, "Can't open '", filename, "' for writing: ", msg)
          LC.mutex.unlock("web.configure")
          return false, "Can't open '" .. filename .. "' for writing: " .. msg
        end
        LC.liveconfig.writeHeader(fh)
        fh:write("# Created at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
        fh:write("# ----------------------------------------------------------------------------\n\n")

        fh:write([[
DirIcons="../icon"
StyleSheet="../awstats/awstats.css"
HTMLHeadSection="<div id="dLCNav"><iframe src="../awstats-nav.html" scrolling="no"></iframe></div>"
HTMLEndSection="<div class="dLiveConfig"><a href="http://www.liveconfig.com" title="LiveConfig Server Control Panel"><img src="../awstats/liveconfig.png" width="137" height="32" alt="powered by LiveConfig"/></a></div>"
SkipHosts="0.0.0.0"

LogType=W
LogFormat=1
LogSeparator=" "
HostAliases="localhost 127.0.0.1"
DNSLookup=0
DirCgi="cgi-bin"
AllowToUpdateStatsFromBrowser=0
AllowFullYearView=2

ShowMenu=1
ShowSummary=UVPHB
ShowMonthStats=UVPHB
ShowDaysOfMonthStats=VPHB
ShowDaysOfWeekStats=PHB
ShowHoursStats=PHB
ShowDomainsStats=PHB
ShowHostsStats=PHBL
ShowAuthenticatedUsers=0
ShowRobotsStats=HBL
ShowWormsStats=0
ShowEMailSenders=0
ShowEMailReceivers=0
ShowSessionsStats=1
ShowPagesStats=PBEX
ShowFileTypesStats=HB
ShowFileSizesStats=0
ShowDownloadsStats=HB
ShowOSStats=1
ShowBrowsersStats=1
ShowScreenSizeStats=0
ShowOriginStats=PH
ShowKeyphrasesStats=1
ShowKeywordsStats=1
ShowMiscStats=a
ShowHTTPErrorsStats=1
ShowSMTPErrorsStats=0
ShowClusterStats=0
ShowFlagLinks=""
ShowLinksOnUrl=1

LoadPlugin="hashfiles"

]])

        LC.liveconfig.writeFooter(fh)
        fh:close()
      end

      -- create config file
      local filename = "/etc/awstats/liveconfig/awstats." .. opts.name .. ".conf"
      local tempfile = filename .. ".tmp"
      local fh, msg = io.open(tempfile, "w")
      if fh == nil then
        LC.log.print(LC.log.ERR, "Can't open '", tempfile, "' for writing: ", msg)
        LC.mutex.unlock("web.configure")
        return false, "Can't open '" .. tempfile .. "' for writing: " .. msg
      end
      LC.liveconfig.writeHeader(fh)
      fh:write("# Created at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
      fh:write("# ----------------------------------------------------------------------------\n\n")

      fh:write("LogFile=\"", opts.path, "/logs/access.log\"\n")
      fh:write("SiteDomain=\"", opts.name, "\"\n")
      fh:write("DirData=\"", opts.path, "/stats\"\n")
      if opts.language ~= nil then
        fh:write("Lang=\"", opts.language, "\"\n")
      else
        fh:write("Lang=\"de\"\n")
      end

      fh:write("\nInclude \"/etc/awstats/liveconfig/awstats.conf.liveconfig\"\n\n")

      LC.liveconfig.writeFooter(fh)
      fh:close()

      -- rename config file (atomic)
      LC.fs.rename(tempfile, filename)

    else
      -- delete AWStats config file (if existing)
      os.remove("/etc/awstats/liveconfig/awstats." .. opts.name .. ".conf")
    end
  end

  LC.mutex.unlock("web.configure")
  return true

end

-- ---------------------------------------------------------------------------
-- updatePasswd()
--
-- Create/update
-- ---------------------------------------------------------------------------
function updatePasswd(opts)

  local fh, res, msg, user

  -- get group name under which web server runs
  local wwwuser, wwwgroup = getWebUser()

  LC.mutex.lock("web.updatePasswd")

  LC.log.print(LC.log.DEBUG, "LC.web.updatePasswd()")

  -- check options
  if opts == nil or opts.name == nil then
    LC.mutex.unlock("web.updatePasswd")
    return false, "No or invalid options specified"
  end

  if opts.users == nil then
    -- no users/passwords defined, delete .htpasswd if existing
    if LC.fs.is_file(opts.path .. "/conf/.htpasswd") then
      os.remove(opts.path .. "/conf/.htpasswd")
    end
    LC.mutex.unlock("web.updatePasswd")
    return true
  end

  -- create destination path (if not existing)
  if opts.path == nil then
    LC.mutex.unlock("web.updatePasswd")
    return false, "No webspace path defined"
  end
  if not LC.fs.is_dir(opts.path .. "/conf") then
    LC.fs.mkdir(opts.path .. "/conf")
    LC.fs.setperm(opts.path .. "/conf", 750, wwwuser, opts.group)
  end

  -- open temporary output file
  fh, msg = io.open(opts.path .. "/conf/.htpasswd.tmp", "w")
  if fh == nil then
    LC.mutex.unlock("web.updatePasswd")
    LC.log.print(LC.log.ERR, "Can't open '", opts.path .. "/conf/.htpasswd.tmp' for writing: ", msg)
    return false, "Can't open '", opts.path .. "/conf/.htpasswd.tmp' for writing: " .. msg
  end

  for user in pairs(opts.users) do
    fh:write(user, ":", opts.users[user], "\n")
  end

  fh:close()

  -- adjust owner and permissions
  LC.fs.setperm(opts.path .. "/conf/.htpasswd.tmp", 440, wwwuser, opts.group)

  -- rename temporary .htpasswd file
  LC.fs.rename(opts.path .. "/conf/.htpasswd.tmp", opts.path .. "/conf/.htpasswd")

  LC.mutex.unlock("web.updatePasswd")
  return true

end

-- ---------------------------------------------------------------------------
-- addPHP()
--
-- Register PHP version
-- ---------------------------------------------------------------------------
function addPHP(code, bin, version, prio)

  -- check that this binary exists:
  if not LC.fs.is_file(bin) then
    return false
  end

  -- priority: 0=default version, 1=additional version
  if prio == nil then
    prio = 1
  end

  local handle = io.popen(bin .. " -v", "r")
  if handle == nil then
    -- can't execute PHP binary
    return false
  end

  local ret = handle:read("*a")
  handle:close()
  if ret ~= nil then
    local v_major, v_minor, v_patch = string.match(ret, "^PHP (%d+)%.(%d+)%.(%d+)")
    local v_int = tonumber(v_major) * 10000 + tonumber(v_minor) * 100 + tonumber(v_patch)
    local inifile = nil
    if v_int >= 50204 then
      -- get location of default php.ini file
      handle = io.popen("echo '<?php echo php_ini_loaded_file(); ?>' | " .. bin .. " -q", "r")
      ret = handle:read("*a")
      handle:close()
      if LC.fs.is_file(ret) then
        inifile = ret
      else
        LC.log.print(LC.log.ERR, "Can't get default php.ini location from " .. bin)
      end
    end
    if code == nil then
      -- default PHP version
      code = "php" .. v_major
      --prio = 0
    end

    -- check if this version (code!) is already configured:
    local p
    for p in pairs(phplist) do
      if phplist[p].code == code then return end
    end

    -- if no explicit version is set, use detected version
    if version == nil then
      version = v_major .. "." .. v_minor .. "." .. v_patch
    end
    phplist[#phplist+1] = {
      ["code"]        = code,
      ["bin"]         = bin,
      ["version"]     = version,
      ["versionInt"]  = v_int,
      ["ini"]         = inifile,
      ["prio"]        = prio
    }
  end

end

-- ---------------------------------------------------------------------------
-- getPHP()
--
-- Get list with available PHP versions
-- ---------------------------------------------------------------------------
function getPHP()
  return LCS.web.phpVersions
end

-- <EOF>----------------------------------------------------------------------
