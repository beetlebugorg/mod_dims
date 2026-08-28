-- wrk script. Reads the signed request paths that run.sh precomputes and
-- rotates through them. Bash signs the dims4 requests because Lua has no md5.
local paths = {}
for line in io.lines("/urls.txt") do
  if #line > 0 then paths[#paths + 1] = line end
end
local n = 0
request = function()
  n = (n % #paths) + 1
  return wrk.format("GET", paths[n])
end
