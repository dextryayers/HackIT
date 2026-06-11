# 🛡️ HackIT Autonomous AI Hunter Report

**Target:** `tesla.com`
**Scan Time:** `2026-06-11 04:34:36`

## 1. Executive Summary
The AI Hunter has successfully completed an autonomous attack simulation on tesla.com. The target is VULNERABLE. 68 active attack vectors were identified and successfully simulated.

## 2. Attack Vectors & Flowchart
### Vulnerability Flowchart: tesla.com

```mermaid
flowchart TD
    Target["🎯 tesla.com"]

    Port80_0("🔌 Port 80 (http/https)")
    Vuln80_0{"🧨 Sensitive Endpoint Exposed: /dump.sql (HTTP 403)"}
    Impact80_0["🔥 High - Data Leakage / RCE"]
    Target --> Port80_0
    Port80_0 -- "Analyzed" --> Vuln80_0
    Vuln80_0 -. "Exploited" .-> Impact80_0

    style Impact80_0 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_1("🔌 Port 80 (http/https)")
    Vuln80_1{"🧨 Sensitive Endpoint Exposed: /.env (HTTP 403)"}
    Impact80_1["🔥 High - Data Leakage / RCE"]
    Target --> Port80_1
    Port80_1 -- "Analyzed" --> Vuln80_1
    Vuln80_1 -. "Exploited" .-> Impact80_1

    style Impact80_1 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_2("🔌 Port 80 (http/https)")
    Vuln80_2{"🧨 Sensitive Endpoint Exposed: /config.php.bak (HTTP 403)"}
    Impact80_2["🔥 High - Data Leakage / RCE"]
    Target --> Port80_2
    Port80_2 -- "Analyzed" --> Vuln80_2
    Vuln80_2 -. "Exploited" .-> Impact80_2

    style Impact80_2 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_3("🔌 Port 80 (http/https)")
    Vuln80_3{"🧨 Sensitive Endpoint Exposed: /.idea/ (HTTP 403)"}
    Impact80_3["🔥 High - Data Leakage / RCE"]
    Target --> Port80_3
    Port80_3 -- "Analyzed" --> Vuln80_3
    Vuln80_3 -. "Exploited" .-> Impact80_3

    style Impact80_3 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_4("🔌 Port 80 (http/https)")
    Vuln80_4{"🧨 Sensitive Endpoint Exposed: /db.sql (HTTP 403)"}
    Impact80_4["🔥 High - Data Leakage / RCE"]
    Target --> Port80_4
    Port80_4 -- "Analyzed" --> Vuln80_4
    Vuln80_4 -. "Exploited" .-> Impact80_4

    style Impact80_4 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_5("🔌 Port 80 (http/https)")
    Vuln80_5{"🧨 Sensitive Endpoint Exposed: /.git/ (HTTP 403)"}
    Impact80_5["🔥 High - Data Leakage / RCE"]
    Target --> Port80_5
    Port80_5 -- "Analyzed" --> Vuln80_5
    Vuln80_5 -. "Exploited" .-> Impact80_5

    style Impact80_5 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_6("🔌 Port 80 (http/https)")
    Vuln80_6{"🧨 Sensitive Endpoint Exposed: /.git/config (HTTP 403)"}
    Impact80_6["🔥 High - Data Leakage / RCE"]
    Target --> Port80_6
    Port80_6 -- "Analyzed" --> Vuln80_6
    Vuln80_6 -. "Exploited" .-> Impact80_6

    style Impact80_6 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_7("🔌 Port 80 (http/https)")
    Vuln80_7{"🧨 Sensitive Endpoint Exposed: /wp-config.php.save (HTTP 403)"}
    Impact80_7["🔥 High - Data Leakage / RCE"]
    Target --> Port80_7
    Port80_7 -- "Analyzed" --> Vuln80_7
    Vuln80_7 -. "Exploited" .-> Impact80_7

    style Impact80_7 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_8("🔌 Port 80 (http/https)")
    Vuln80_8{"🧨 Sensitive Endpoint Exposed: /.env.local (HTTP 403)"}
    Impact80_8["🔥 High - Data Leakage / RCE"]
    Target --> Port80_8
    Port80_8 -- "Analyzed" --> Vuln80_8
    Vuln80_8 -. "Exploited" .-> Impact80_8

    style Impact80_8 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_9("🔌 Port 80 (http/https)")
    Vuln80_9{"🧨 Sensitive Endpoint Exposed: /database.sql (HTTP 403)"}
    Impact80_9["🔥 High - Data Leakage / RCE"]
    Target --> Port80_9
    Port80_9 -- "Analyzed" --> Vuln80_9
    Vuln80_9 -. "Exploited" .-> Impact80_9

    style Impact80_9 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_10("🔌 Port 80 (http/https)")
    Vuln80_10{"🧨 Sensitive Endpoint Exposed: /.env.dev (HTTP 403)"}
    Impact80_10["🔥 High - Data Leakage / RCE"]
    Target --> Port80_10
    Port80_10 -- "Analyzed" --> Vuln80_10
    Vuln80_10 -. "Exploited" .-> Impact80_10

    style Impact80_10 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_11("🔌 Port 80 (http/https)")
    Vuln80_11{"🧨 Sensitive Endpoint Exposed: /.svn/ (HTTP 403)"}
    Impact80_11["🔥 High - Data Leakage / RCE"]
    Target --> Port80_11
    Port80_11 -- "Analyzed" --> Vuln80_11
    Vuln80_11 -. "Exploited" .-> Impact80_11

    style Impact80_11 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_12("🔌 Port 80 (http/https)")
    Vuln80_12{"🧨 Sensitive Endpoint Exposed: /.env.backup (HTTP 403)"}
    Impact80_12["🔥 High - Data Leakage / RCE"]
    Target --> Port80_12
    Port80_12 -- "Analyzed" --> Vuln80_12
    Vuln80_12 -. "Exploited" .-> Impact80_12

    style Impact80_12 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_13("🔌 Port 80 (http/https)")
    Vuln80_13{"🧨 Sensitive Endpoint Exposed: /backup.sql (HTTP 403)"}
    Impact80_13["🔥 High - Data Leakage / RCE"]
    Target --> Port80_13
    Port80_13 -- "Analyzed" --> Vuln80_13
    Vuln80_13 -. "Exploited" .-> Impact80_13

    style Impact80_13 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_14("🔌 Port 80 (http/https)")
    Vuln80_14{"🧨 Sensitive Endpoint Exposed: /backup.tar.gz (HTTP 403)"}
    Impact80_14["🔥 High - Data Leakage / RCE"]
    Target --> Port80_14
    Port80_14 -- "Analyzed" --> Vuln80_14
    Vuln80_14 -. "Exploited" .-> Impact80_14

    style Impact80_14 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_15("🔌 Port 80 (http/https)")
    Vuln80_15{"🧨 Sensitive Endpoint Exposed: /backup.zip (HTTP 403)"}
    Impact80_15["🔥 High - Data Leakage / RCE"]
    Target --> Port80_15
    Port80_15 -- "Analyzed" --> Vuln80_15
    Vuln80_15 -. "Exploited" .-> Impact80_15

    style Impact80_15 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_16("🔌 Port 80 (http/https)")
    Vuln80_16{"🧨 Sensitive Endpoint Exposed: /.vscode/ (HTTP 403)"}
    Impact80_16["🔥 High - Data Leakage / RCE"]
    Target --> Port80_16
    Port80_16 -- "Analyzed" --> Vuln80_16
    Vuln80_16 -. "Exploited" .-> Impact80_16

    style Impact80_16 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_17("🔌 Port 80 (http/https)")
    Vuln80_17{"🧨 Sensitive Endpoint Exposed: /phpinfo.php (HTTP 403)"}
    Impact80_17["🔥 High - Data Leakage / RCE"]
    Target --> Port80_17
    Port80_17 -- "Analyzed" --> Vuln80_17
    Vuln80_17 -. "Exploited" .-> Impact80_17

    style Impact80_17 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_18("🔌 Port 80 (http/https)")
    Vuln80_18{"🧨 Sensitive Endpoint Exposed: /wp-config.php.bak (HTTP 403)"}
    Impact80_18["🔥 High - Data Leakage / RCE"]
    Target --> Port80_18
    Port80_18 -- "Analyzed" --> Vuln80_18
    Vuln80_18 -. "Exploited" .-> Impact80_18

    style Impact80_18 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_19("🔌 Port 80 (http/https)")
    Vuln80_19{"🧨 Sensitive Endpoint Exposed: /server-status (HTTP 403)"}
    Impact80_19["🔥 High - Data Leakage / RCE"]
    Target --> Port80_19
    Port80_19 -- "Analyzed" --> Vuln80_19
    Vuln80_19 -. "Exploited" .-> Impact80_19

    style Impact80_19 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_20("🔌 Port 80 (http/https)")
    Vuln80_20{"🧨 Sensitive Endpoint Exposed: /wp-admin/admin-ajax.php (HTTP 403)"}
    Impact80_20["🔥 High - Data Leakage / RCE"]
    Target --> Port80_20
    Port80_20 -- "Analyzed" --> Vuln80_20
    Vuln80_20 -. "Exploited" .-> Impact80_20

    style Impact80_20 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_21("🔌 Port 80 (http/https)")
    Vuln80_21{"🧨 Sensitive Endpoint Exposed: /login/ (HTTP 403)"}
    Impact80_21["🔥 High - Data Leakage / RCE"]
    Target --> Port80_21
    Port80_21 -- "Analyzed" --> Vuln80_21
    Vuln80_21 -. "Exploited" .-> Impact80_21

    style Impact80_21 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_22("🔌 Port 80 (http/https)")
    Vuln80_22{"🧨 Sensitive Endpoint Exposed: /info.php (HTTP 403)"}
    Impact80_22["🔥 High - Data Leakage / RCE"]
    Target --> Port80_22
    Port80_22 -- "Analyzed" --> Vuln80_22
    Vuln80_22 -. "Exploited" .-> Impact80_22

    style Impact80_22 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_23("🔌 Port 80 (http/https)")
    Vuln80_23{"🧨 Sensitive Endpoint Exposed: /admin/ (HTTP 403)"}
    Impact80_23["🔥 High - Data Leakage / RCE"]
    Target --> Port80_23
    Port80_23 -- "Analyzed" --> Vuln80_23
    Vuln80_23 -. "Exploited" .-> Impact80_23

    style Impact80_23 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_24("🔌 Port 80 (http/https)")
    Vuln80_24{"🧨 Sensitive Endpoint Exposed: /v2/api-docs (HTTP 403)"}
    Impact80_24["🔥 High - Data Leakage / RCE"]
    Target --> Port80_24
    Port80_24 -- "Analyzed" --> Vuln80_24
    Vuln80_24 -. "Exploited" .-> Impact80_24

    style Impact80_24 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_25("🔌 Port 80 (http/https)")
    Vuln80_25{"🧨 Sensitive Endpoint Exposed: /actuator/health (HTTP 403)"}
    Impact80_25["🔥 High - Data Leakage / RCE"]
    Target --> Port80_25
    Port80_25 -- "Analyzed" --> Vuln80_25
    Vuln80_25 -. "Exploited" .-> Impact80_25

    style Impact80_25 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_26("🔌 Port 80 (http/https)")
    Vuln80_26{"🧨 Sensitive Endpoint Exposed: /graphql (HTTP 403)"}
    Impact80_26["🔥 High - Data Leakage / RCE"]
    Target --> Port80_26
    Port80_26 -- "Analyzed" --> Vuln80_26
    Vuln80_26 -. "Exploited" .-> Impact80_26

    style Impact80_26 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_27("🔌 Port 80 (http/https)")
    Vuln80_27{"🧨 Sensitive Endpoint Exposed: /dashboard/ (HTTP 403)"}
    Impact80_27["🔥 High - Data Leakage / RCE"]
    Target --> Port80_27
    Port80_27 -- "Analyzed" --> Vuln80_27
    Vuln80_27 -. "Exploited" .-> Impact80_27

    style Impact80_27 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_28("🔌 Port 80 (http/https)")
    Vuln80_28{"🧨 Sensitive Endpoint Exposed: /api/v1/users.json (HTTP 403)"}
    Impact80_28["🔥 High - Data Leakage / RCE"]
    Target --> Port80_28
    Port80_28 -- "Analyzed" --> Vuln80_28
    Vuln80_28 -. "Exploited" .-> Impact80_28

    style Impact80_28 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_29("🔌 Port 80 (http/https)")
    Vuln80_29{"🧨 Sensitive Endpoint Exposed: /actuator/env (HTTP 403)"}
    Impact80_29["🔥 High - Data Leakage / RCE"]
    Target --> Port80_29
    Port80_29 -- "Analyzed" --> Vuln80_29
    Vuln80_29 -. "Exploited" .-> Impact80_29

    style Impact80_29 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_30("🔌 Port 80 (http/https)")
    Vuln80_30{"🧨 Sensitive Endpoint Exposed: /administrator/ (HTTP 403)"}
    Impact80_30["🔥 High - Data Leakage / RCE"]
    Target --> Port80_30
    Port80_30 -- "Analyzed" --> Vuln80_30
    Vuln80_30 -. "Exploited" .-> Impact80_30

    style Impact80_30 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_31("🔌 Port 80 (http/https)")
    Vuln80_31{"🧨 Sensitive Endpoint Exposed: /api/v1/users (HTTP 403)"}
    Impact80_31["🔥 High - Data Leakage / RCE"]
    Target --> Port80_31
    Port80_31 -- "Analyzed" --> Vuln80_31
    Vuln80_31 -. "Exploited" .-> Impact80_31

    style Impact80_31 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port80_32("🔌 Port 80 (http/https)")
    Vuln80_32{"🧨 Sensitive Endpoint Exposed: /swagger-ui.html (HTTP 403)"}
    Impact80_32["🔥 High - Data Leakage / RCE"]
    Target --> Port80_32
    Port80_32 -- "Analyzed" --> Vuln80_32
    Vuln80_32 -. "Exploited" .-> Impact80_32

    style Impact80_32 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_33("🔌 Port 443 (http/https)")
    Vuln443_33{"🧨 Sensitive Endpoint Exposed: /wp-config.php.bak (HTTP 403)"}
    Impact443_33["🔥 High - Data Leakage / RCE"]
    Target --> Port443_33
    Port443_33 -- "Analyzed" --> Vuln443_33
    Vuln443_33 -. "Exploited" .-> Impact443_33

    style Impact443_33 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_34("🔌 Port 443 (http/https)")
    Vuln443_34{"🧨 Sensitive Endpoint Exposed: /.idea/ (HTTP 403)"}
    Impact443_34["🔥 High - Data Leakage / RCE"]
    Target --> Port443_34
    Port443_34 -- "Analyzed" --> Vuln443_34
    Vuln443_34 -. "Exploited" .-> Impact443_34

    style Impact443_34 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_35("🔌 Port 443 (http/https)")
    Vuln443_35{"🧨 Sensitive Endpoint Exposed: /.svn/ (HTTP 403)"}
    Impact443_35["🔥 High - Data Leakage / RCE"]
    Target --> Port443_35
    Port443_35 -- "Analyzed" --> Vuln443_35
    Vuln443_35 -. "Exploited" .-> Impact443_35

    style Impact443_35 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_36("🔌 Port 443 (http/https)")
    Vuln443_36{"🧨 Sensitive Endpoint Exposed: /.git/config (HTTP 403)"}
    Impact443_36["🔥 High - Data Leakage / RCE"]
    Target --> Port443_36
    Port443_36 -- "Analyzed" --> Vuln443_36
    Vuln443_36 -. "Exploited" .-> Impact443_36

    style Impact443_36 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_37("🔌 Port 443 (http/https)")
    Vuln443_37{"🧨 Sensitive Endpoint Exposed: /.git/ (HTTP 403)"}
    Impact443_37["🔥 High - Data Leakage / RCE"]
    Target --> Port443_37
    Port443_37 -- "Analyzed" --> Vuln443_37
    Vuln443_37 -. "Exploited" .-> Impact443_37

    style Impact443_37 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_38("🔌 Port 443 (http/https)")
    Vuln443_38{"🧨 Sensitive Endpoint Exposed: /backup.zip (HTTP 403)"}
    Impact443_38["🔥 High - Data Leakage / RCE"]
    Target --> Port443_38
    Port443_38 -- "Analyzed" --> Vuln443_38
    Vuln443_38 -. "Exploited" .-> Impact443_38

    style Impact443_38 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_39("🔌 Port 443 (http/https)")
    Vuln443_39{"🧨 Sensitive Endpoint Exposed: /config.php.bak (HTTP 403)"}
    Impact443_39["🔥 High - Data Leakage / RCE"]
    Target --> Port443_39
    Port443_39 -- "Analyzed" --> Vuln443_39
    Vuln443_39 -. "Exploited" .-> Impact443_39

    style Impact443_39 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_40("🔌 Port 443 (http/https)")
    Vuln443_40{"🧨 Sensitive Endpoint Exposed: /.vscode/ (HTTP 403)"}
    Impact443_40["🔥 High - Data Leakage / RCE"]
    Target --> Port443_40
    Port443_40 -- "Analyzed" --> Vuln443_40
    Vuln443_40 -. "Exploited" .-> Impact443_40

    style Impact443_40 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_41("🔌 Port 443 (http/https)")
    Vuln443_41{"🧨 Sensitive Endpoint Exposed: /database.sql (HTTP 403)"}
    Impact443_41["🔥 High - Data Leakage / RCE"]
    Target --> Port443_41
    Port443_41 -- "Analyzed" --> Vuln443_41
    Vuln443_41 -. "Exploited" .-> Impact443_41

    style Impact443_41 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_42("🔌 Port 443 (http/https)")
    Vuln443_42{"🧨 Sensitive Endpoint Exposed: /db.sql (HTTP 403)"}
    Impact443_42["🔥 High - Data Leakage / RCE"]
    Target --> Port443_42
    Port443_42 -- "Analyzed" --> Vuln443_42
    Vuln443_42 -. "Exploited" .-> Impact443_42

    style Impact443_42 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_43("🔌 Port 443 (http/https)")
    Vuln443_43{"🧨 Sensitive Endpoint Exposed: /.env (HTTP 403)"}
    Impact443_43["🔥 High - Data Leakage / RCE"]
    Target --> Port443_43
    Port443_43 -- "Analyzed" --> Vuln443_43
    Vuln443_43 -. "Exploited" .-> Impact443_43

    style Impact443_43 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_44("🔌 Port 443 (http/https)")
    Vuln443_44{"🧨 Sensitive Endpoint Exposed: /.env.backup (HTTP 403)"}
    Impact443_44["🔥 High - Data Leakage / RCE"]
    Target --> Port443_44
    Port443_44 -- "Analyzed" --> Vuln443_44
    Vuln443_44 -. "Exploited" .-> Impact443_44

    style Impact443_44 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_45("🔌 Port 443 (http/https)")
    Vuln443_45{"🧨 Sensitive Endpoint Exposed: /dump.sql (HTTP 403)"}
    Impact443_45["🔥 High - Data Leakage / RCE"]
    Target --> Port443_45
    Port443_45 -- "Analyzed" --> Vuln443_45
    Vuln443_45 -. "Exploited" .-> Impact443_45

    style Impact443_45 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_46("🔌 Port 443 (http/https)")
    Vuln443_46{"🧨 Sensitive Endpoint Exposed: /backup.tar.gz (HTTP 403)"}
    Impact443_46["🔥 High - Data Leakage / RCE"]
    Target --> Port443_46
    Port443_46 -- "Analyzed" --> Vuln443_46
    Vuln443_46 -. "Exploited" .-> Impact443_46

    style Impact443_46 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_47("🔌 Port 443 (http/https)")
    Vuln443_47{"🧨 Sensitive Endpoint Exposed: /.env.local (HTTP 403)"}
    Impact443_47["🔥 High - Data Leakage / RCE"]
    Target --> Port443_47
    Port443_47 -- "Analyzed" --> Vuln443_47
    Vuln443_47 -. "Exploited" .-> Impact443_47

    style Impact443_47 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_48("🔌 Port 443 (http/https)")
    Vuln443_48{"🧨 Sensitive Endpoint Exposed: /phpinfo.php (HTTP 403)"}
    Impact443_48["🔥 High - Data Leakage / RCE"]
    Target --> Port443_48
    Port443_48 -- "Analyzed" --> Vuln443_48
    Vuln443_48 -. "Exploited" .-> Impact443_48

    style Impact443_48 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_49("🔌 Port 443 (http/https)")
    Vuln443_49{"🧨 Sensitive Endpoint Exposed: /wp-config.php.save (HTTP 403)"}
    Impact443_49["🔥 High - Data Leakage / RCE"]
    Target --> Port443_49
    Port443_49 -- "Analyzed" --> Vuln443_49
    Vuln443_49 -. "Exploited" .-> Impact443_49

    style Impact443_49 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_50("🔌 Port 443 (http/https)")
    Vuln443_50{"🧨 Sensitive Endpoint Exposed: /.env.dev (HTTP 403)"}
    Impact443_50["🔥 High - Data Leakage / RCE"]
    Target --> Port443_50
    Port443_50 -- "Analyzed" --> Vuln443_50
    Vuln443_50 -. "Exploited" .-> Impact443_50

    style Impact443_50 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_51("🔌 Port 443 (http/https)")
    Vuln443_51{"🧨 Sensitive Endpoint Exposed: /backup.sql (HTTP 403)"}
    Impact443_51["🔥 High - Data Leakage / RCE"]
    Target --> Port443_51
    Port443_51 -- "Analyzed" --> Vuln443_51
    Vuln443_51 -. "Exploited" .-> Impact443_51

    style Impact443_51 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_52("🔌 Port 443 (http/https)")
    Vuln443_52{"🧨 Sensitive Endpoint Exposed: /server-status (HTTP 403)"}
    Impact443_52["🔥 High - Data Leakage / RCE"]
    Target --> Port443_52
    Port443_52 -- "Analyzed" --> Vuln443_52
    Vuln443_52 -. "Exploited" .-> Impact443_52

    style Impact443_52 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_53("🔌 Port 443 (http/https)")
    Vuln443_53{"🧨 Sensitive Endpoint Exposed: /admin/ (HTTP 403)"}
    Impact443_53["🔥 High - Data Leakage / RCE"]
    Target --> Port443_53
    Port443_53 -- "Analyzed" --> Vuln443_53
    Vuln443_53 -. "Exploited" .-> Impact443_53

    style Impact443_53 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_54("🔌 Port 443 (http/https)")
    Vuln443_54{"🧨 Sensitive Endpoint Exposed: /api/v1/users (HTTP 403)"}
    Impact443_54["🔥 High - Data Leakage / RCE"]
    Target --> Port443_54
    Port443_54 -- "Analyzed" --> Vuln443_54
    Vuln443_54 -. "Exploited" .-> Impact443_54

    style Impact443_54 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_55("🔌 Port 443 (http/https)")
    Vuln443_55{"🧨 Sensitive Endpoint Exposed: /swagger-ui.html (HTTP 403)"}
    Impact443_55["🔥 High - Data Leakage / RCE"]
    Target --> Port443_55
    Port443_55 -- "Analyzed" --> Vuln443_55
    Vuln443_55 -. "Exploited" .-> Impact443_55

    style Impact443_55 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_56("🔌 Port 443 (http/https)")
    Vuln443_56{"🧨 Sensitive Endpoint Exposed: /dashboard/ (HTTP 403)"}
    Impact443_56["🔥 High - Data Leakage / RCE"]
    Target --> Port443_56
    Port443_56 -- "Analyzed" --> Vuln443_56
    Vuln443_56 -. "Exploited" .-> Impact443_56

    style Impact443_56 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_57("🔌 Port 443 (http/https)")
    Vuln443_57{"🧨 Sensitive Endpoint Exposed: /graphql (HTTP 403)"}
    Impact443_57["🔥 High - Data Leakage / RCE"]
    Target --> Port443_57
    Port443_57 -- "Analyzed" --> Vuln443_57
    Vuln443_57 -. "Exploited" .-> Impact443_57

    style Impact443_57 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_58("🔌 Port 443 (http/https)")
    Vuln443_58{"🧨 Sensitive Endpoint Exposed: /login/ (HTTP 403)"}
    Impact443_58["🔥 High - Data Leakage / RCE"]
    Target --> Port443_58
    Port443_58 -- "Analyzed" --> Vuln443_58
    Vuln443_58 -. "Exploited" .-> Impact443_58

    style Impact443_58 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_59("🔌 Port 443 (http/https)")
    Vuln443_59{"🧨 Sensitive Endpoint Exposed: /api/v1/users.json (HTTP 403)"}
    Impact443_59["🔥 High - Data Leakage / RCE"]
    Target --> Port443_59
    Port443_59 -- "Analyzed" --> Vuln443_59
    Vuln443_59 -. "Exploited" .-> Impact443_59

    style Impact443_59 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_60("🔌 Port 443 (http/https)")
    Vuln443_60{"🧨 Sensitive Endpoint Exposed: /administrator/ (HTTP 403)"}
    Impact443_60["🔥 High - Data Leakage / RCE"]
    Target --> Port443_60
    Port443_60 -- "Analyzed" --> Vuln443_60
    Vuln443_60 -. "Exploited" .-> Impact443_60

    style Impact443_60 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_61("🔌 Port 443 (http/https)")
    Vuln443_61{"🧨 Sensitive Endpoint Exposed: /info.php (HTTP 403)"}
    Impact443_61["🔥 High - Data Leakage / RCE"]
    Target --> Port443_61
    Port443_61 -- "Analyzed" --> Vuln443_61
    Vuln443_61 -. "Exploited" .-> Impact443_61

    style Impact443_61 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_62("🔌 Port 443 (http/https)")
    Vuln443_62{"🧨 Sensitive Endpoint Exposed: /actuator/health (HTTP 403)"}
    Impact443_62["🔥 High - Data Leakage / RCE"]
    Target --> Port443_62
    Port443_62 -- "Analyzed" --> Vuln443_62
    Vuln443_62 -. "Exploited" .-> Impact443_62

    style Impact443_62 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_63("🔌 Port 443 (http/https)")
    Vuln443_63{"🧨 Sensitive Endpoint Exposed: /wp-admin/admin-ajax.php (HTTP 403)"}
    Impact443_63["🔥 High - Data Leakage / RCE"]
    Target --> Port443_63
    Port443_63 -- "Analyzed" --> Vuln443_63
    Vuln443_63 -. "Exploited" .-> Impact443_63

    style Impact443_63 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_64("🔌 Port 443 (http/https)")
    Vuln443_64{"🧨 Sensitive Endpoint Exposed: /v2/api-docs (HTTP 403)"}
    Impact443_64["🔥 High - Data Leakage / RCE"]
    Target --> Port443_64
    Port443_64 -- "Analyzed" --> Vuln443_64
    Vuln443_64 -. "Exploited" .-> Impact443_64

    style Impact443_64 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port443_65("🔌 Port 443 (http/https)")
    Vuln443_65{"🧨 Sensitive Endpoint Exposed: /actuator/env (HTTP 403)"}
    Impact443_65["🔥 High - Data Leakage / RCE"]
    Target --> Port443_65
    Port443_65 -- "Analyzed" --> Vuln443_65
    Vuln443_65 -. "Exploited" .-> Impact443_65

    style Impact443_65 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
    Port21_66("🔌 Port 21 (ftp)")
    Vuln21_66{"🧨 Anonymous FTP Login Check"}
    Impact21_66["🔥 Medium - Unauthorized Data Access"]
    Target --> Port21_66
    Port21_66 -- "Analyzed" --> Vuln21_66
    Vuln21_66 -. "Exploited" .-> Impact21_66

    style Impact21_66 fill:#f90,stroke:#333,stroke-width:2px,color:#fff
    Port3306_67("🔌 Port 3306 (mysql)")
    Vuln3306_67{"🧨 MySQL Default Credentials / Blank Password Check"}
    Impact3306_67["🔥 Critical - Database Compromise"]
    Target --> Port3306_67
    Port3306_67 -- "Analyzed" --> Vuln3306_67
    Vuln3306_67 -. "Exploited" .-> Impact3306_67

    style Impact3306_67 fill:#f00,stroke:#333,stroke-width:4px,color:#fff
```


## 3. Detailed Findings
### 3.1. Sensitive Endpoint Exposed: /dump.sql (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.2. Sensitive Endpoint Exposed: /.env (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.3. Sensitive Endpoint Exposed: /config.php.bak (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.4. Sensitive Endpoint Exposed: /.idea/ (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.5. Sensitive Endpoint Exposed: /db.sql (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.6. Sensitive Endpoint Exposed: /.git/ (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.7. Sensitive Endpoint Exposed: /.git/config (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.8. Sensitive Endpoint Exposed: /wp-config.php.save (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.9. Sensitive Endpoint Exposed: /.env.local (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.10. Sensitive Endpoint Exposed: /database.sql (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.11. Sensitive Endpoint Exposed: /.env.dev (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.12. Sensitive Endpoint Exposed: /.svn/ (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.13. Sensitive Endpoint Exposed: /.env.backup (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.14. Sensitive Endpoint Exposed: /backup.sql (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.15. Sensitive Endpoint Exposed: /backup.tar.gz (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.16. Sensitive Endpoint Exposed: /backup.zip (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.17. Sensitive Endpoint Exposed: /.vscode/ (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.18. Sensitive Endpoint Exposed: /phpinfo.php (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.19. Sensitive Endpoint Exposed: /wp-config.php.bak (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.20. Sensitive Endpoint Exposed: /server-status (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.21. Sensitive Endpoint Exposed: /wp-admin/admin-ajax.php (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.22. Sensitive Endpoint Exposed: /login/ (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.23. Sensitive Endpoint Exposed: /info.php (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.24. Sensitive Endpoint Exposed: /admin/ (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.25. Sensitive Endpoint Exposed: /v2/api-docs (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.26. Sensitive Endpoint Exposed: /actuator/health (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.27. Sensitive Endpoint Exposed: /graphql (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.28. Sensitive Endpoint Exposed: /dashboard/ (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.29. Sensitive Endpoint Exposed: /api/v1/users.json (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.30. Sensitive Endpoint Exposed: /actuator/env (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.31. Sensitive Endpoint Exposed: /administrator/ (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.32. Sensitive Endpoint Exposed: /api/v1/users (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.33. Sensitive Endpoint Exposed: /swagger-ui.html (HTTP 403) on Port 80
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.34. Sensitive Endpoint Exposed: /wp-config.php.bak (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.35. Sensitive Endpoint Exposed: /.idea/ (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.36. Sensitive Endpoint Exposed: /.svn/ (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.37. Sensitive Endpoint Exposed: /.git/config (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.38. Sensitive Endpoint Exposed: /.git/ (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.39. Sensitive Endpoint Exposed: /backup.zip (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.40. Sensitive Endpoint Exposed: /config.php.bak (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.41. Sensitive Endpoint Exposed: /.vscode/ (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.42. Sensitive Endpoint Exposed: /database.sql (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.43. Sensitive Endpoint Exposed: /db.sql (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.44. Sensitive Endpoint Exposed: /.env (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.45. Sensitive Endpoint Exposed: /.env.backup (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.46. Sensitive Endpoint Exposed: /dump.sql (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.47. Sensitive Endpoint Exposed: /backup.tar.gz (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.48. Sensitive Endpoint Exposed: /.env.local (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.49. Sensitive Endpoint Exposed: /phpinfo.php (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.50. Sensitive Endpoint Exposed: /wp-config.php.save (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.51. Sensitive Endpoint Exposed: /.env.dev (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.52. Sensitive Endpoint Exposed: /backup.sql (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.53. Sensitive Endpoint Exposed: /server-status (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.54. Sensitive Endpoint Exposed: /admin/ (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.55. Sensitive Endpoint Exposed: /api/v1/users (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.56. Sensitive Endpoint Exposed: /swagger-ui.html (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.57. Sensitive Endpoint Exposed: /dashboard/ (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.58. Sensitive Endpoint Exposed: /graphql (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.59. Sensitive Endpoint Exposed: /login/ (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.60. Sensitive Endpoint Exposed: /api/v1/users.json (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.61. Sensitive Endpoint Exposed: /administrator/ (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.62. Sensitive Endpoint Exposed: /info.php (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.63. Sensitive Endpoint Exposed: /actuator/health (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.64. Sensitive Endpoint Exposed: /wp-admin/admin-ajax.php (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.65. Sensitive Endpoint Exposed: /v2/api-docs (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.66. Sensitive Endpoint Exposed: /actuator/env (HTTP 403) on Port 443
- **Service:** http/https
- **Impact:** High - Data Leakage / RCE
- **Status:** `Verified by AI`

### 3.67. Anonymous FTP Login Check on Port 21
- **Service:** ftp
- **Impact:** Medium - Unauthorized Data Access
- **Status:** `Verified by AI`

### 3.68. MySQL Default Credentials / Blank Password Check on Port 3306
- **Service:** mysql
- **Impact:** Critical - Database Compromise
- **Status:** `Verified by AI`

## 4. Conclusion & Remediation
**Conclusion:**
The target exhibits significant security flaws that allow for active exploitation. Immediate patching and network isolation are required.

**Remediation:**
1. Update all identified vulnerable services.
2. Restrict public access to administrative ports.
3. Implement WAF to filter malicious payloads.
