--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2013 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/distribution.lua
-- Distribution detection
-- $Id: distribution.lua 2855 2014-04-29 15:34:36Z kk $
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local LCS = LCS
local io = io
local os = os
local ipairs = ipairs
local string = string
local table = table

-- Module declaration
module("distribution")

-- Exported functions
-- detect()
-- getPackageVersion(pkgname)

-- Exported variables
name        = nil     -- Distribution name      (eg. "Ubuntu")
codename    = nil     -- Distribution code name (eg. "lucid")
version     = nil     -- Version number         (eg. "10.04")
family      = nil     -- Distribution family    (eg. "Debian")
description = nil     -- additional description (eg. "Ubuntu 10.04.1 LTS")

-- ---------------------------------------------------------------------------
-- detect_lsb()
-- ---------------------------------------------------------------------------
local function detect_lsb()
  local handle, errmsg, errno  = io.popen("/usr/bin/lsb_release -a 2>/dev/null", "r")
  if handle == nil then
    return false
  end
  local t = handle:read("*all")
  handle:close()
  local d = string.match(t, "Distributor ID:%s*([^\n]+)")
  if d == nil then
    return false
  end
  name = d
  description = string.match(t, "Description:%s*([^\n]+)")
  version = string.match(t, "Release:%s*([^\n]+)")
  codename = string.match(t, "Codename:%s*([^\n]+)")
  if name == "Debian" or name == "Ubuntu" then
    family = "Debian"
  elseif name == "CentOS" then 
    family = "RedHat"
  elseif name == "SUSE LINUX" then 
    family = "SUSE"
  else
    return false
  end
  return true
end

-- ---------------------------------------------------------------------------
-- detect_debian()
-- ---------------------------------------------------------------------------
local function detect_debian()
  -- this function should be called *after* detect_lsb() !
  local handle, errmsg, errno = io.open("/etc/debian_version", "r")
  if handle == nil then
    return false
  end
  local t = handle:read("*all")
  handle:close()
  local v = string.match(t, "^%d+%.%d+%.%d+") or string.match(t, "^%d+%.%d+")
  if v == nil then
    -- if version is not numeric, then we propably have a Debian Testing/Unstable or Ubuntu distribution
    if LC.fs.is_file("/usr/share/apt/ubuntu-archive.gpg") then
      -- this is propably a Ubuntu system
      family = "Debian"
      name = "Ubuntu"
      -- ###BAUSTELLE### version
      -- ###BAUSTELLE### description
      -- ###BAUSTELLE### codename
      return true
    end
    if LC.fs.is_file("/etc/apt/trusted.gpg.d/debian-archive-wheezy-stable.gpg") then
      -- Debian 7.0 (Wheezy)
      family = "Debian"
      name = "Debian"
      version = "7.0"
      description = "Debian GNU/Linux 7.0 (wheezy)"
      codename = "wheezy"
    end
    return false
  end
  family = "Debian"
  name = "Debian"
  version = v
  description = name .. " GNU/Linux " .. version

  if codename == nil then
    -- try to get codename manually (using major+minor version number)
    v = string.match(version, "^%d+")
    if v == "4" then
      codename = "Etch"
    elseif v == "5" then
      codename = "Lenny"
    elseif v == "6" then
      codename = "Squeeze"
    elseif v == "7" then
      codename = "Wheezy"
    elseif v == "8" then
      codename = "Jessie"
    end
  end
  if codename ~= nil then
    description = description .. " (" .. codename .. ")"
  end

  return true
end

-- ---------------------------------------------------------------------------
-- detect_suse()
-- ---------------------------------------------------------------------------
local function detect_suse()
  local handle, errmsg, errno = io.open("/etc/SuSE-release", "r")
  if handle == nil then
    return false
  end
  family = "SUSE"
  local t = handle:read("*all")
  handle:close()
  local v = string.match(t, "VERSION = (%d+%.%d+)")
  if v == nil then
    return false
  end
  codename = string.match(t, "CODENAME = ([^\n]+)")
  name = "openSUSE"
  version = v
  description = string.match(t, "^(openSUSE [^\n]+)")
  return true
end

-- ---------------------------------------------------------------------------
-- detect_centos()
-- ---------------------------------------------------------------------------
local function detect_centos()
  local handle, errmsg, errno = io.open("/etc/redhat-release", "r")
  if handle == nil then
    return false
  end

  family = "RedHat"
  local t = handle:read("*all")
  handle:close()
  local v = string.match(t, "(%d+%.%d+)")
  if v == nil then
    return false
  end
  name = "CentOS"
  version = v
  description = string.match(t, "^(CentOS [^\n]+)")
  return true
end

-- ---------------------------------------------------------------------------
-- detect_solaris()
-- ---------------------------------------------------------------------------
local function detect_solaris()
  local handle, errmsg, errno = io.open("/etc/release", "r")
  if handle == nil then
    return false
  end
  family = "SunOS"
  local t = handle.read(handle)
  handle:close()
--  local v = string.match(t, "(%d+%.%d+)")
  local v = LC.sys.get_release()
  if v == nil then
    return false
  end
  name = "OpenSolaris"
  version = v
  description = string.match(t, "(OpenSolaris [^\n]+)")
  return true
end

-- ---------------------------------------------------------------------------
-- detect_bsd()
-- ---------------------------------------------------------------------------
local function detect_bsd()
  family = "BSD"
  local v = LC.sys.get_release()
  if v == nil then
    return false
  end
  name = "FreeBSD"
  version = v
  description = "FreeBSD (" .. v .. ")"
  return true
end

-- ---------------------------------------------------------------------------
-- detect_gentoo()
-- ---------------------------------------------------------------------------

local function detect_gentoo()
  local handle, errmsg, errno = io.open("/etc/gentoo-release", "r")
  if handle == nil then
    return false
  end
  local t = handle:read("*all")
  handle:close()
  local v = string.match(t, "^Gentoo Base System release (%d+%.%d+[%d%.]*)")
  if v == nil then
    return false
  end

  family = "Gentoo"
  version = v
  name = "Gentoo"
  description = "Gentoo GNU/Linux " .. version
  return true
end

-- ---------------------------------------------------------------------------
-- detect()
-- ---------------------------------------------------------------------------
function detect()

  -- check if distribution was already detected; avoid double-detection
  -- also across multiple threads
  --LC.mutex.debug(true)

  LC.mutex.lock("distribution.detect")

  if LCS.distribution ~= nil then
    -- distribution already detected; load values from global LCS storage
    LC.mutex.unlock("distribution.detect")
    LC.distribution.name        = LCS.distribution.name
    LC.distribution.codename    = LCS.distribution.codename
    LC.distribution.version     = LCS.distribution.version
    LC.distribution.family      = LCS.distribution.family
    LC.distribution.description = LCS.distribution.description
    return true
  end

  -- if previous detection failed, just try again (maybe we have
  -- more luck this time)
  local detected = false

  if (LC.sys.get_name() == "Linux") then
    if detect_lsb() or detect_debian() or detect_suse() or detect_centos() or detect_gentoo() then
      detected = true
    end
  elseif (LC.sys.get_name() == "SunOS") then
    if detect_solaris() then
      detected = true
    end
  elseif (LC.sys.get_name() == "FreeBSD") then
    if detect_bsd() then
      detected = true
    end
  else
    -- print ("OS detection not possible")
    LC.log.print(LC.log.ERR, "Unsupported operating system '", LC.sys.get_name(), "' - no detection possible")
  end

  if detected then
    LC.log.print(LC.log.INFO, "Detected '", description, "'")
    -- save detected values in global storage (LCS)
    LCS.distribution = {
      name        = LC.distribution.name,
      codename    = LC.distribution.codename,
      version     = LC.distribution.version,
      family      = LC.distribution.family,
      description = LC.distribution.description
    }
  end

  LC.mutex.unlock("distribution.detect")

  return detected

end 

-- ---------------------------------------------------------------------------
-- getPackageVersion()
-- ---------------------------------------------------------------------------
function getPackageVersion(pkgname)

  if family == "Debian" then
    local handle = io.popen("dpkg-query -f='${Package} ${Status} ${Version}\n' -W " .. pkgname, "r")
    local ret = handle:read("*a")
    handle:close()
    local pkg, s1, s2, s3, v = string.match(ret, "^([^%s]+) ([^%s]+) ([^%s]+) ([^%s]+) ([^%s]+)")
    if s3 == "installed" and v ~= nil then
      return v
    end
  end

  if family == "Gentoo" then
    local handle = io.popen("emerge --nospinner --search \"%^" .. pkgname .. "$\" | grep \"Latest version installed\"")
    local ret = handle: read("*a")
    handle:close()
    local pkg_ver = string.match(ret,"%d+%.%d+%.%d+")
    if pkg_ver ~= nil then
      return pkg_ver
    end
  end

  if family == "BSD" then
    local handle io.popen("pkg_info | grep \"^" .. pkgname .. "\"")
    local ret = handle: read("*a")
    handle:close()
    local pkg_ver = string.match(ret,"[^%s]+%-([^%s]+)")
    if pkg_ver ~= nil then
      return pkg_ver
    end
  end

  return nil
end

-- ---------------------------------------------------------------------------
-- hasPackage()
-- ---------------------------------------------------------------------------
function hasPackage(...)

  if LC.distribution.family == "Debian" then
    -- check a list of package names using "dpkg-query"
    -- we supply an own format string for easier status parsing
    local cmd = "/usr/bin/dpkg-query -f='${Package} ${Status} ${Version}\n' -W"
    for i, pkg in ipairs{...} do
      cmd = cmd .. " " .. pkg
    end
    local handle = io.popen(cmd .. " 2>/dev/null", "r")
    for line in handle:lines() do
      local pkg, s1, s2, s3, v = string.match(line, "^([^%s]+) ([^%s]+) ([^%s]+) ([^%s]+) ([^%s]+)")
      -- LC.log.print(LC.log.DEBUG, "LC.distribution.hasPackage: '", pkg, "' is ", s3)
      if s3 == "installed" or s3 == "unpacked" then
        -- ok, we found an installed package. abort here.
        handle:close()
        return pkg, v
      end
    end
    handle:close()
  end

  if LC.distribution.family == "RedHat" or LC.distribution.family == "SUSE" then
    -- check a list of package names using "rpm"
    -- we supply an own format string for easier status parsing
    local cmd = "/bin/rpm -q --queryformat '%{Name} %{Version}\n'"
    for i, pkg in ipairs{...} do
      cmd = cmd .. " " .. pkg
    end
    local handle = io.popen(cmd .. " 2>/dev/null", "r")
    for line in handle:lines() do
      local pkg, v = string.match(line, "^([^%s]+) ([^%s]+)")
      local state = string.find(line,"not installed",1,true)
      if state == nil then
        -- ok, we found an installed package. get version number
        handle:close()
        return pkg, v
      end
    end
    handle:close()
  end

  if LC.distribution.family == "BSD" then
    -- check a list of package names using "pkg_info"
    local cmd = "/usr/sbin/pkg_info | grep '"
    for i, pkg in ipairs{...} do
      if i > 1 then cmd = cmd .. "\\|" end
      cmd = cmd .. "^" .. pkg
    end
    cmd = cmd .. "'"
    -- LC.log.print(LC.log.DEBUG, "CMD: ", cmd)
    local handle = io.popen( cmd .. " 2>/dev/null", "r")
    for line in handle:lines() do
      -- LC.log.print(LC.log.DEBUG, line)
      -- ok, we found an installed package. get version number
      local pkg, v = string.match(line, "^([^%.]+)%-([^%s]+)")
      handle:close()
      return pkg, v
    end
    handle:close()
  end

  if LC.distribution.family == "Gentoo" then

    if LC.fs.is_file("/usr/bin/eix") then
      -- eix existiert -> schneller -> nutzen
      local cmd = "HOME=\"/\" /usr/bin/eix -en "
      local v

      cmd = cmd .. table.concat({...}, " -o ")

--      LC.log.print(LC.log.DEBUG, cmd)
      local handle = io.popen(cmd, "r")

      for line in handle:lines() do
        local paket = string.match(line, "^%[[^%]]%] ([^\n]+)")

        if paket ~= nil then
--          LC.log.print(LC.log.DEBUG, paket)
          pkg = paket
        end

        local version = string.match(line,"^     Installed versions:  ([^%(]+)")

        if version ~= nil then
--          LC.log.print(LC.log.DEBUG, version)
          v = version
        end
      end

      if v ~= nil then
--        LC.log.print(LC.log.DEBUG, "installed!")
        return pkg, v
      end
--      LC.log.print(LC.log.DEBUG, "not installed!")
    else
      -- gibt nur emerge --search
      local cmd = "/usr/bin/emerge --color n --search --nospinner"
      local pkg
      local v
      for i, pkg in ipairs{...} do
        cmd = cmd .. " %^" .. pkg .. "$"
      end
--      LC.log.print(LC.log.DEBUG, cmd)
      local handle = io.popen(cmd, "r")

      for line in handle:lines() do
        --LC.log.print(LC.log.DEBUG, line)
        local paket = string.match(line, "^*  ([^\n]+)$")
        if paket ~= nil then
--          LC.log.print(LC.log.DEBUG, paket)
          pkg = paket
        end
        local version = string.match(line, "^      Latest version installed: ([^\n]+)")
        if version ~= nil and version ~= "[ Not Installed ]" then
--          LC.log.print(LC.log.DEBUG, version)
          v = version
        end
      end

      if v ~= nil then
--        LC.log.print(LC.log.DEBUG, "installed!")
        return pkg, v
      end

--      LC.log.print(LC.log.DEBUG, "not installed!")
  
    end
  end

  return nil
end

-- <EOF>----------------------------------------------------------------------
