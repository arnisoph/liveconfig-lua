--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/hooks.lua
-- Callback hooks
-- $Id: hooks.lua 1312 2012-02-02 12:35:04Z kk $
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local LCS = LCS

-- Module declaration
module("hooks")

-- Exported functions
--   register()
--   check()
--   update()
--   add()

local version = 0
local register_list = { }
local hook_list = { }

LC.mutex.lock("hooks")
if LCS.hooks == nil then
  LCS.hooks = {
    version = 0
  }
end
LC.mutex.unlock("hooks")

-- ---------------------------------------------------------------------------
-- register()
--
-- Register functions from modules, which are responsible for registering
-- callback handles
-- All registered functions are called again whenever the LCS.hooks.version
-- number has changed
-- ---------------------------------------------------------------------------
function register(fn)
  -- check if function is already registered
  local i
  for i=1, #register_list do
    if register_list[i] == fn then
      return
    end
  end

  -- register function
  register_list[#register_list+1] = fn
end

-- ---------------------------------------------------------------------------
-- check()
--
-- Check for hooks with given name, and run them eventually
-- ---------------------------------------------------------------------------
function check(name, ...)
  local i
  LC.mutex.lock("hooks")
  if LCS.hooks.version > version then
--    LC.log.print(LC.log.INFO, "Updating hooks list...")
    -- re-run all callback registering functions
    for i=1, #register_list do
      register_list[i]()
    end

    -- update local hooks version
    version = LCS.hooks.version
  end
  LC.mutex.unlock("hooks")

  if hook_list[name] then
    for i=1, #hook_list[name] do
--      LC.log.print(LC.log.INFO, "Running hook '", name, "'")
      hook_list[name][i](...)
    end
  end

end

-- ---------------------------------------------------------------------------
-- update()
--
-- Mark hook list as "dirty" (all register handlers will be run again on
-- next check() call)
-- ---------------------------------------------------------------------------
function update()
  LC.mutex.lock("hooks")
  LCS.hooks.version = LCS.hooks.version + 1
  LC.mutex.unlock("hooks")
end

-- ---------------------------------------------------------------------------
-- add()
--
-- Add a hook function
-- ---------------------------------------------------------------------------
function add(name, fn)
  if hook_list[name] == nil then
    hook_list[name] = { }
  end
  -- check if already registered
  local i
  for i=1, #hook_list[name] do
    if hook_list[name][i] == fn then
      return
    end
  end
  -- add hook
  hook_list[name][#hook_list[name]+1] = fn
end

-- <EOF>----------------------------------------------------------------------
