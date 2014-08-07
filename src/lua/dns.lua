--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/dns.lua
-- DNS server management
-- $Id: dns.lua 2694 2013-12-03 11:30:21Z kk $
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local LCS = LCS
local require = require
local pairs = pairs
local os = os

-- Module declaration
module("dns")

-- Exported functions
-- load()
-- detect()
-- getConfig()
-- install()
-- uninstall()
-- configure()
-- update()

-- Exported variables
-- LC.dns.NS_T_* constants
-- LC.dns.NS_TYPES array

NS_T_A      = 1
NS_T_NS     = 2
NS_T_CNAME  = 5
NS_T_PTR    = 12
NS_T_MX     = 15
NS_T_TXT    = 16
NS_T_AAAA   = 28

NS_TYPES = {
  [NS_T_A]      = "A",
  [NS_T_NS]     = "NS",
  [NS_T_CNAME]  = "CNAME",
  [NS_T_PTR]    = "PTR",
  [NS_T_MX]     = "MX",
  [NS_T_TXT]    = "TXT",
  [NS_T_AAAA]   = "AAAA",
}

-- ---------------------------------------------------------------------------

-- module variables
local modlist = { }

-- ---------------------------------------------------------------------------
-- load(modname)
--
-- Load "driver" module for a specific dns server
-- ---------------------------------------------------------------------------
function load(mod)
  modlist[mod] = require(mod)
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect installed dns server packages
-- (currently: bind)
-- ---------------------------------------------------------------------------
function detect()
  local data = {}
  local mod

  -- check if dns server software was already detected; avoid double-detection
  -- also across multiple threads
  LC.mutex.lock("dns.detect")

  if LCS.dns ~= nil then
    if LCS.dns.data ~= nil then
      -- dns server software already detected; load values from global LCS storage
      LC.mutex.unlock("dns.detect")
      return LCS.dns.data
    end
  end

  -- run detection handler for all installed driver modules
  LC.log.print(LC.log.DEBUG, "running dns.detect()");
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

  LCS.dns = {
    generated = true,
    data      = data    -- LCS.dns.data = (local)data
  }

  LC.mutex.unlock("dns.detect")
  
  return data
end

-- ---------------------------------------------------------------------------
-- getConfig()
--
-- Return configuration table for specified nameserver
-- (eg. "bind" or "powerdns")
-- ---------------------------------------------------------------------------
function getConfig(name)
  local w = detect()
  local i = 1;
  while w[i] do
    if w[i]['type'] == name then
      return w[i]
    end
    i=i+1
  end
end

-- ---------------------------------------------------------------------------
-- install()
--
-- Start management of nameserver
-- ---------------------------------------------------------------------------
function install(config, opts)
  if config == nil or config.type == nil then
    return false, "dns.install(): no configuration submitted"
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for nameserver '", config.type, "' found")
    return false, "No module for nameserver '" .. config.type .. "' found"
  end

  -- run install() function from nameserver module
  return modlist[config.type].install(config, opts)
end

-- ---------------------------------------------------------------------------
-- uninstall()
--
-- Stop management of nameserver
-- ---------------------------------------------------------------------------
function uninstall(opts)

  LC.log.print(LC.log.DEBUG, "LC.dns.uninstall()")

  -- check options
  if opts == nil or opts.server == nil then
    return false, "No nameserver specified"
  end

  -- get configuration
  local cfg = getConfig(opts.server)
  if cfg == nil then
    return false, "Nameserver '" .. opts.server .. "' not found"
  end

  if modlist[cfg.type] == nil then
    LC.log.print(LC.log.ERR, "No module for nameserver '", cfg.type, "' found")
    return false
  end
  if not modlist[cfg.type].uninstall(cfg, opts) then
    return false
  end
  return true
end

-- ---------------------------------------------------------------------------
-- configure()
--
-- Configure nameserver
-- ---------------------------------------------------------------------------
function configure(opts)

  LC.log.print(LC.log.DEBUG, "LC.dns.configure()")

  local res, msg
  -- check options
  if opts == nil or opts.server == nil then
    return false, "No nameserver specified"
  end

  -- get configuration
  local cfg = getConfig(opts.server)
  if cfg == nil then
    return false, "Nameserver '" .. opts.server .. "' not found"
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
  end

  -- update core configuration
  res, msg = modlist[cfg.type].configure(cfg, opts)
  if not res then
    return false, msg
  end

  -- restart nameserver
  LC.log.print(LC.log.DEBUG, "Reload cmd: ", cfg.reload_cmd)
  if cfg.reload_cmd ~= nil then
    local rc = os.execute(cfg.reload_cmd)
    LC.log.print(LC.log.DEBUG, "Return value: ", rc)
    if rc ~= 0 then
      return false, "Error while reloading configuration (exit code: " .. rc .. ")"
    end
  end

  return true
end

-- ---------------------------------------------------------------------------
-- update()
--
-- Update DNS configuration (add/remove/update zone or RRs)
-- ---------------------------------------------------------------------------
function update(data)
  local cfg = getConfig('bind')
  if cfg == nil then
    return false, 'No nameserver configured.'
  end

  if data.cmd == 'addZone' then
    return modlist[cfg.type].addZone(cfg, data)
  elseif data.cmd == 'updateKeys' then
    return modlist[cfg.type].updateKeys(cfg, data)
  elseif data.cmd == 'updateZone' then
    return modlist[cfg.type].updateZone(cfg, data)
  elseif data.cmd == 'delZone' then
    return modlist[cfg.type].delZone(cfg, data)
  else
    -- command not found / not supported
    LC.log.print(LC.log.ERR, "LC.dns.update(): unknown command '", data.cmd, "'")
    return false, "LC.dns.update(): unknown command '" .. data.cmd .. "'"
  end

end

-- <EOF>----------------------------------------------------------------------