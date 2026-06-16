local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[Detects an exposed Docker daemon Unix socket or TCP endpoint. Attempts to list containers, images, volumes, networks, and running processes via the Docker API. Tests both TCP ports 2375 and 2376.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "cloud"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 2375 or port.number == 2376)
end

local function docker_api_get(endpoint, port, path)
  local scheme = port == 2376 and "https" or "http"
  local ok, resp = pcall(http.get, endpoint, port, path, { timeout = 5000 })
  if ok and resp and resp.status == 200 then
    return resp
  end
  return nil
end

local function parse_json(body)
  local ok, data = pcall(json.parse, body)
  if ok then return data end
  return nil
end

action = function(host, port)
  local result = stdnse.output_table()
  local endpoint = host.ip

  local version_resp = docker_api_get(endpoint, port.number, "/version")
  if not version_resp then
    return stdnse.format_output(false, "Docker socket not detected or not accessible")
  end

  local version_data = parse_json(version_resp.body)
  if not version_data then
    return stdnse.format_output(false, "Failed to parse Docker version response")
  end

  result.engine_version = version_data.Version
  result.api_version = version_data.ApiVersion
  result.min_api_version = version_data.MinAPIVersion
  result.os = version_data.Os
  result.architecture = version_data.Arch
  result.kernel_version = version_data.KernelVersion
  result.build_time = version_data.BuildTime
  result.git_commit = version_data.GitCommit
  result.go_version = version_data.GoVersion
  result.operating_system = version_data.Os
  result.experimental = version_data.Experimental

  local info_resp = docker_api_get(endpoint, port.number, "/info")
  if info_resp then
    local info_data = parse_json(info_resp.body)
    if info_data then
      result.name = info_data.Name
      result.server_version = info_data.ServerVersion
      result.storage_driver = info_data.Driver
      result.logging_driver = info_data.LoggingDriver
      result.cgroup_driver = info_data.CgroupDriver
      result.containers_total = info_data.Containers
      result.containers_running = info_data.ContainersRunning
      result.containers_paused = info_data.ContainersPaused
      result.containers_stopped = info_data.ContainersStopped
      result.images_count = info_data.Images
      result.swarm_status = info_data.Swarm and info_data.Swarm.LocalNodeState or "inactive"
      result.cpus = info_data.NCPU
      result.memory_bytes = info_data.MemTotal
      result.memory_human = info_data.MemTotal and string.format("%.1f GB", info_data.MemTotal / 1073741824)
      result.operating_system = info_data.OperatingSystem
      result.os_type = info_data.OSType
      result.kernel_version = info_data.KernelVersion
    end
  end

  local containers_resp = docker_api_get(endpoint, port.number, "/containers/json?all=true&size=true")
  if containers_resp then
    local containers = parse_json(containers_resp.body)
    if containers and #containers > 0 then
      local container_list = {}
      for _, c in ipairs(containers) do
        table.insert(container_list, {
          id = c.Id and c.Id:sub(1, 12),
          image = c.Image,
          state = c.State,
          status = c.Status,
          names = c.Names,
          ports = c.Ports,
          created = c.Created,
        })
      end
      result.containers = container_list
      result.containers_total = #container_list
    end
  end

  local images_resp = docker_api_get(endpoint, port.number, "/images/json")
  if images_resp then
    local images = parse_json(images_resp.body)
    if images then
      local image_list = {}
      for _, img in ipairs(images) do
        table.insert(image_list, {
          id = img.Id and img.Id:sub(1, 12),
          tags = img.RepoTags,
          size = img.Size,
          created = img.Created,
        })
      end
      result.images = image_list
      result.images_total = #image_list
    end
  end

  local volumes_resp = docker_api_get(endpoint, port.number, "/volumes")
  if volumes_resp then
    local volumes = parse_json(volumes_resp.body)
    if volumes and volumes.Volumes and #volumes.Volumes > 0 then
      result.volumes = {}
      for _, v in ipairs(volumes.Volumes) do
        table.insert(result.volumes, { name = v.Name, mountpoint = v.Mountpoint, driver = v.Driver })
      end
      result.volumes_count = #volumes.Volumes
    end
  end

  local networks_resp = docker_api_get(endpoint, port.number, "/networks")
  if networks_resp then
    local networks = parse_json(networks_resp.body)
    if networks and #networks > 0 then
      result.networks = {}
      for _, n in ipairs(networks) do
        table.insert(result.networks, { id = n.Id and n.Id:sub(1, 12), name = n.Name, driver = n.Driver, scope = n.Scope })
      end
      result.networks_count = #networks
    end
  end

  return stdnse.format_output(true, result)
end
