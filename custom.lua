-- Env vars
dovecot.NOUPDATE = true
postfix.NOUPDATE = true

php_versions = {
  php53 = {
    bin = "/usr/bin/php53/php-cgi",
    alias = "5.3",
  },
  php54 = {
    bin = "/usr/bin/php54/php-cgi",
    alias = "5.4",
  },
  php55 = {
    bin = "/usr/bin/php55/php-cgi",
    alias = "5.5",
    prio = 0,
  },
  php56 = {
    bin = "/usr/bin/php56/php-cgi",
    alias = "5.6",
  },
}


-- Magic goes below

for k, v in pairs(php_versions) do
  if v.bin ~= nil and LC.fs.is_file(v.bin) then
    local alias = nil
    local prio = nil

    if v.alias ~= nil then
      alias = v.alias
    end

    if v.prio ~= nil then
      prio = v.prio
    end

    LC.web.addPHP(k, v.bin, alias, prio)
  end
end
