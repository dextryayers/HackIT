require 'socket'
require 'timeout'
require 'json'

module HackIT
  class VulnCheck
    VULNERABILITIES = [
      { cve: 'CVE-2017-0144', severity: 'CRITICAL', port: 445, service: 'SMB', match: /Windows\s*[57]|SMB\s*v1/i, desc: 'EternalBlue - SMB Remote Code Execution' },
      { cve: 'CVE-2019-0708', severity: 'CRITICAL', port: 3389, service: 'RDP', match: /MSRDP|Terminal\s*Server\s*2008|Windows\s*7\s*Enterprise/i, desc: 'BlueKeep - RDP Remote Code Execution' },
      { cve: 'CVE-2020-1472', severity: 'CRITICAL', port: 389, service: 'Netlogon', match: /Windows\s*Server\s*2008|Windows\s*Server\s*2012|Windows\s*Server\s*2016/i, desc: 'Zerologon - Netlogon Elevation of Privilege' },
      { cve: 'CVE-2014-0160', severity: 'CRITICAL', port: 443, service: 'HTTPS', match: /OpenSSL\/1\.0\.1[a-f]/i, desc: 'Heartbleed - OpenSSL Information Disclosure' },
      { cve: 'CVE-2014-6271', severity: 'CRITICAL', port: 80, service: 'HTTP', match: /bash|Bash|Shellshock/i, desc: 'Shellshock - Bash Remote Code Execution' },
      { cve: 'CVE-2015-1427', severity: 'CRITICAL', port: 9200, service: 'Elasticsearch', match: /Elasticsearch\s*1\.\d/i, desc: 'Elasticsearch Groovy Sandbox Bypass' },
      { cve: 'CVE-2021-44228', severity: 'CRITICAL', port: 0, service: 'Java', match: /Log4j|log4j/i, desc: 'Log4Shell - Apache Log4j Remote Code Execution' },
      { cve: 'CVE-2020-5902', severity: 'CRITICAL', port: 443, service: 'F5 BIG-IP', match: /BIG-IP|F5/i, desc: 'F5 BIG-IP TMUI RCE' },
      { cve: 'CVE-2021-26855', severity: 'CRITICAL', port: 443, service: 'Exchange', match: /Microsoft\s*Exchange\s*Server\s*2013|Exchange\s*2016|Exchange\s*2019/i, desc: 'ProxyLogon - Exchange Server SSRF' },
      { cve: 'CVE-2019-2725', severity: 'CRITICAL', port: 7001, service: 'WebLogic', match: /WebLogic|Oracle/i, desc: 'Oracle WebLogic Deserialization RCE' },
      { cve: 'CVE-2017-5638', severity: 'CRITICAL', port: 8080, service: 'Struts', match: /Struts|Apache\s*Struts/i, desc: 'Apache Struts2 OGNL Injection' },
      { cve: 'CVE-2021-22986', severity: 'HIGH', port: 443, service: 'BIG-IP', match: /BIG-IP\s*(1[4-6]|1[0-3])/i, desc: 'F5 BIG-IP iControl REST RCE' },
      { cve: 'CVE-2020-7961', severity: 'HIGH', port: 443, service: 'Liferay', match: /Liferay/i, desc: 'Liferay Portal RCE' },
      { cve: 'CVE-2021-21972', severity: 'HIGH', port: 443, service: 'vCenter', match: /VMware\s*vCenter|vCenter\s*Server/i, desc: 'vCenter Server RCE' },
      { cve: 'CVE-2020-16898', severity: 'HIGH', port: 0, service: 'Windows', match: /Windows\s*10\s*1[789]0|Windows\s*Server\s*2019/i, desc: 'Bad Neighbor - Windows TCP/IP RCE' },
      { cve: 'CVE-2020-0796', severity: 'HIGH', port: 445, service: 'SMB', match: /Windows\s*10\s*1903|Windows\s*10\s*1909/i, desc: 'SMBGhost - SMBv3 Compression RCE' },
      { cve: 'CVE-2021-1675', severity: 'HIGH', port: 445, service: 'Print Spooler', match: /Windows\s*Server\s*(2016|2019|2022)/i, desc: 'PrintNightmare - Print Spooler RCE' },
      { cve: 'CVE-2018-4878', severity: 'HIGH', port: 80, service: 'Flash', match: /flash|Adobe\s*Flash/i, desc: 'Adobe Flash Player RCE' },
      { cve: 'CVE-2019-11510', severity: 'HIGH', port: 443, service: 'Pulse VPN', match: /Pulse\s*Secure|Pulse\s*Connect/i, desc: 'Pulse Secure VPN Arbitrary File Read' },
      { cve: 'CVE-2020-3452', severity: 'HIGH', port: 443, service: 'Cisco ASA', match: /Cisco\s*ASA|Cisco\s*FTD/i, desc: 'Cisco ASA/FTD Path Traversal' },
      { cve: 'CVE-2019-19781', severity: 'HIGH', port: 443, service: 'Citrix', match: /Citrix\s*ADC|Citrix\s*Gateway|NetScaler/i, desc: 'Citrix ADC/Gateway Directory Traversal' },
      { cve: 'CVE-2018-13379', severity: 'HIGH', port: 443, service: 'Fortinet', match: /Fortinet|FortiGate|FortiOS/i, desc: 'Fortinet SSL VPN Path Traversal' },
      { cve: 'CVE-2019-1652', severity: 'HIGH', port: 443, service: 'Cisco', match: /Cisco\s*RV\d+|Cisco\s*Small\s*Business/i, desc: 'Cisco RV Series Path Traversal' },
      { cve: 'CVE-2020-8193', severity: 'HIGH', port: 443, service: 'Citrix', match: /Citrix\s*ADC\s*1[123]/i, desc: 'Citrix ADC Unauthenticated Access' },
      { cve: 'CVE-2021-31166', severity: 'HIGH', port: 80, service: 'HTTP.sys', match: /Windows\s*10\s*20H2|Windows\s*Server\s*20H2/i, desc: 'HTTP Protocol Stack RCE' },
      { cve: 'CVE-2018-7600', severity: 'CRITICAL', port: 80, service: 'Drupal', match: /Drupal\s*7|Drupal\s*8\.\d/i, desc: 'Drupalgeddon2 - Drupal Core RCE' },
      { cve: 'CVE-2017-10271', severity: 'CRITICAL', port: 7001, service: 'WebLogic', match: /WebLogic\s*10\.3\.6|WebLogic\s*12\.1\.3/i, desc: 'WebLogic WLS RCE' },
      { cve: 'CVE-2017-7494', severity: 'CRITICAL', port: 445, service: 'Samba', match: /Samba\s*4\.\d\.\d/i, desc: 'SambaCry - Samba RCE' },
      { cve: 'CVE-2019-0215', severity: 'HIGH', port: 80, service: 'Apache', match: /Apache\s*2\.4\.(3[789]|4[0-9])/i, desc: 'Apache httpd Privilege Escalation' },
      { cve: 'CVE-2019-9511', severity: 'HIGH', port: 80, service: 'HTTP/2', match: /HTTP\/2|h2c/i, desc: 'HTTP/2 Downgrade Attack' },
      { cve: 'CVE-2020-11022', severity: 'MEDIUM', port: 80, service: 'jQuery', match: /jQuery\s*<=\s*3\.4|jQuery\s*<=\s*3\.5\.0/i, desc: 'jQuery XSS Vulnerability' },
      { cve: 'CVE-2021-30563', severity: 'MEDIUM', port: 80, service: 'Chrome', match: /Chrome\/8\d|Chrome\/9\d/i, desc: 'Google Chrome V8 RCE' },
      { cve: 'CVE-2020-0601', severity: 'MEDIUM', port: 443, service: 'Windows', match: /Windows\s*10\s*1[5-9]|Windows\s*Server\s*2016|2019/i, desc: 'CurveBall - Windows CryptoAPI Spoofing' },
      { cve: 'CVE-2018-15473', severity: 'MEDIUM', port: 22, service: 'SSH', match: /OpenSSH_[67]\.[0-9]/i, desc: 'OpenSSH Username Enumeration' },
      { cve: 'CVE-2017-7269', severity: 'MEDIUM', port: 80, service: 'IIS', match: /IIS\s*6\.0/i, desc: 'IIS 6.0 WebDAV RCE' },
      { cve: 'CVE-2019-10742', severity: 'MEDIUM', port: 80, service: 'axios', match: /axios/i, desc: 'axios SSRF' },
      { cve: 'CVE-2019-15642', severity: 'MEDIUM', port: 80, service: 'Webmin', match: /Webmin\s*1\.\d{3}/i, desc: 'Webmin RCE' },
      { cve: 'CVE-2020-35489', severity: 'MEDIUM', port: 80, service: 'WordPress', match: /WordPress\s*<=\s*5\.6/i, desc: 'WordPress Contact Form 7 RCE' },
      { cve: 'CVE-2019-16759', severity: 'HIGH', port: 80, service: 'vBulletin', match: /vBulletin\s*5\.\d/i, desc: 'vBulletin Widget Config RCE' },
      { cve: 'CVE-2018-11776', severity: 'HIGH', port: 8080, service: 'Struts', match: /Struts\s*2\.\d/i, desc: 'Apache Struts2 RCE' },
      { cve: 'CVE-2020-25213', severity: 'HIGH', port: 80, service: 'WordPress', match: /WordPress\s*<=\s*5\.5\.1/i, desc: 'WordPress File Manager RCE' },
      { cve: 'CVE-2021-29447', severity: 'HIGH', port: 80, service: 'WordPress', match: /WordPress\s*5\.\d\.\d/i, desc: 'WordPress XSLT Server-Side Injection' },
      { cve: 'CVE-2020-11651', severity: 'CRITICAL', port: 4505, service: 'SaltStack', match: /Salt|salt-master/i, desc: 'SaltStack Master RCE' },
      { cve: 'CVE-2019-1653', severity: 'MEDIUM', port: 443, service: 'Cisco', match: /Cisco\s*RV320|Cisco\s*RV325/i, desc: 'Cisco RV320/RV325 Credential Disclosure' },
      { cve: 'CVE-2020-2551', severity: 'CRITICAL', port: 7001, service: 'WebLogic', match: /WebLogic\s*10\.3\.6|WebLogic\s*12\.(1|2)/i, desc: 'WebLogic WLS Core RCE' },
      { cve: 'CVE-2020-14882', severity: 'CRITICAL', port: 7001, service: 'WebLogic', match: /WebLogic\s*10\.3\.6|WebLogic\s*12\.(1|2|3)/i, desc: 'WebLogic Console RCE' },
      { cve: 'CVE-2021-22986', severity: 'HIGH', port: 443, service: 'F5', match: /BIG-IP\s*1[5-9]|BIG-IP\s*2[0-4]/i, desc: 'F5 BIG-IP iControl REST RCE' },
      { cve: 'CVE-2020-25637', severity: 'HIGH', port: 445, service: 'Samba', match: /Samba\s*4\.\d\.\d/i, desc: 'Samba AD RCE' },
      { cve: 'CVE-2021-30554', severity: 'MEDIUM', port: 80, service: 'WebKit', match: /AppleWebKit/i, desc: 'WebKit Use-After-Free' },
      { cve: 'CVE-2020-13935', severity: 'MEDIUM', port: 80, service: 'Tomcat', match: /Tomcat\s*(8|9|10)/i, desc: 'Apache Tomcat WebSocket DoS' },
      { cve: 'CVE-2020-1938', severity: 'HIGH', port: 8009, service: 'Tomcat AJP', match: /Apache\s*Tomcat/i, desc: 'Ghostcat - Tomcat AJP File Read' },
      { cve: 'CVE-2021-22555', severity: 'HIGH', port: 0, service: 'Linux', match: /Linux\s*kernel\s*5\.\d+/i, desc: 'Linux Kernel Heap Out-of-Bounds Write' },
      { cve: 'CVE-2021-33909', severity: 'HIGH', port: 0, service: 'Linux', match: /Linux\s*kernel\s*5\.\d+/i, desc: 'Linux Kernel seq_file Path Walk RCE' },
      { cve: 'CVE-2021-40444', severity: 'CRITICAL', port: 0, service: 'MSHTML', match: /Windows\s*(10|11|Server)/i, desc: 'MSHTML RCE - Office/IE' },
      { cve: 'CVE-2021-34527', severity: 'CRITICAL', port: 445, service: 'Print Spooler', match: /Windows\s*Server\s*(2012|2016|2019|2022)/i, desc: 'PrintNightmare (variant) - Windows Print Spooler RCE' }
    ]

    def self.plugin_info
      {
        name: 'VulnCheck',
        version: '1.5.0',
        description: 'Vulnerability check engine with 50+ CVE signatures matched via banner/version patterns and port-based risk assessment',
        author: 'HackIT Team'
      }
    end

    def run(target, port = 0, opts = {})
      findings = []
      risk_score = 0
      p = port.to_i

      banners = opts[:banners] || {}

      if p > 0
        result = check_port_vulns(target, p, banners)
        findings.concat(result[:findings])
        risk_score += result[:risk_score]
      else
        common_vuln_ports = VULNERABILITIES.map { |v| v[:port] }.uniq.reject(&:zero?)
        common_vuln_ports.each do |vp|
          begin
            Timeout.timeout(opts[:timeout] || 2) do
              s = TCPSocket.new(target, vp)
              s.close
              result = check_port_vulns(target, vp, banners)
              findings.concat(result[:findings])
              risk_score += result[:risk_score]
            end
          rescue
          end
        end
      end

      findings << 'No vulnerabilities detected' if findings.empty?

      { status: 'completed', findings: findings, risk_score: [risk_score, 100].min }
    end

    private

    def check_port_vulns(target, port, banners)
      findings = []
      risk_score = 0
      matched = []

      VULNERABILITIES.each do |vuln|
        next unless vuln[:port] == 0 || vuln[:port] == port

        matched_vuln = false

        if banners[port] && banners[port].match?(vuln[:match])
          matched_vuln = true
        end

        unless matched_vuln
          begin
            Timeout.timeout(2) do
              s = TCPSocket.new(target, port)
              banner = s.gets(2048).to_s + s.read(1024).to_s rescue banner
              s.close
              if banner.match?(vuln[:match])
                matched_vuln = true
              end
            end
          rescue
          end
        end

        if matched_vuln
          matched << vuln
          score = case vuln[:severity]
          when 'CRITICAL' then 30
          when 'HIGH' then 20
          when 'MEDIUM' then 10
          else 5
          end
          risk_score += score
        end
      end

      matched.each do |v|
        findings << "#{v[:cve]} (#{v[:severity]}): #{v[:desc]}"
      end

      { findings: findings, risk_score: risk_score }
    end
  end
end

if __FILE__ == $0
  target = ARGV[0] || '127.0.0.1'
  port = (ARGV[1] || 0).to_i
  vuln = HackIT::VulnCheck.new
  result = vuln.run(target, port)
  puts JSON.pretty_generate(result)
end
