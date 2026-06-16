local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[Attempts to retrieve instance metadata from the AWS EC2 metadata endpoint at 169.254.169.254. Returns IAM role, instance ID, region, and other metadata if accessible. Tests IMDSv1 and IMDSv2 endpoints with multiple metadata paths.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "cloud"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

local metadata_paths = {
  "instance-id", "ami-id", "hostname", "public-ipv4", "local-ipv4",
  "instance-type", "placement/region", "placement/availability-zone",
  "placement/availability-zone-id", "placement/placement-group-name",
  "network/interfaces/macs/", "services/domain", "services/partition",
  "identity-credentials/ec2/info", "iam/info", "iam/security-credentials/",
  "metrics", "reservation-id", "profile", "kernel-id", "ramdisk-id",
  "product-codes", "public-keys/", "security-groups", "tags/instance/",
}

local function fetch_metadata(base_url, port, path, use_imdsv2, token)
  local headers = {}
  if use_imdsv2 and token then
    headers["X-aws-ec2-metadata-token"] = token
  end
  local ok, response = pcall(http.get, base_url, port, "/latest/meta-data/" .. path, { timeout = 3000, header = headers })
  if ok and response and response.status == 200 and response.body and #response.body > 0 then
    return response.body:gsub("%s+$", "")
  end
  return nil
end

action = function(host, port)
  local result = stdnse.output_table()

  if host.ip ~= "169.254.169.254" then
    return nil
  end

  local base_url = "169.254.169.254"
  local imdsv2_token
  local use_imdsv2 = false

  local ok, token_resp = pcall(http.put, base_url, 80, "/latest/api/token", {
    timeout = 2000,
    header = { ["X-aws-ec2-metadata-token-ttl-seconds"] = "60" },
  })
  if ok and token_resp and token_resp.status == 200 and token_resp.body then
    imdsv2_token = token_resp.body:gsub("%s+$", "")
    use_imdsv2 = true
    result.imdsv2_supported = true
  end

  local ok, test_resp = pcall(http.get, base_url, 80, "/latest/meta-data/", {
    timeout = 3000,
    header = use_imdsv2 and { ["X-aws-ec2-metadata-token"] = imdsv2_token } or {},
  })
  if not ok or not test_resp or test_resp.status ~= 200 then
    return stdnse.format_output(false, "AWS metadata endpoint not accessible")
  end

  for _, path in ipairs(metadata_paths) do
    local val = fetch_metadata(base_url, 80, path, use_imdsv2, imdsv2_token)
    if val then
      result[path:gsub("/", "_"):gsub("-", "_")] = val
    end
  end

  local ok, iam_resp = pcall(http.get, base_url, 80, "/latest/meta-data/iam/security-credentials/", {
    timeout = 3000,
    header = use_imdsv2 and { ["X-aws-ec2-metadata-token"] = imdsv2_token } or {},
  })
  if ok and iam_resp and iam_resp.status == 200 and iam_resp.body and #iam_resp.body > 0 then
    result.iam_roles = iam_resp.body
    local role_name = iam_resp.body:match("(%w+)")
    if role_name then
      local ok2, cred_resp = pcall(http.get, base_url, 80, "/latest/meta-data/iam/security-credentials/" .. role_name, {
        timeout = 3000,
        header = use_imdsv2 and { ["X-aws-ec2-metadata-token"] = imdsv2_token } or {},
      })
      if ok2 and cred_resp and cred_resp.status == 200 then
        local ok3, creds = pcall(json.parse, cred_resp.body)
        if ok3 and creds then
          result.iam_access_key_id = creds.AccessKeyId
          result.iam_secret_key_present = creds.SecretAccessKey and true or nil
          result.iam_token_present = creds.Token and true or nil
          result.iam_expiration = creds.Expiration
        end
      end
    end
  end

  local ok, user_data = pcall(http.get, base_url, 80, "/latest/user-data", {
    timeout = 3000,
    header = use_imdsv2 and { ["X-aws-ec2-metadata-token"] = imdsv2_token } or {},
  })
  if ok and user_data and user_data.status == 200 and user_data.body and #user_data.body > 0 then
    result.user_data_present = true
    result.user_data_size = #user_data.body
  end

  return stdnse.format_output(true, result)
end
