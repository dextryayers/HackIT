#!/usr/bin/env python3
"""Generates the network_recon.rs file"""
import os

path = r"D:\web\hacks\hackstools\hackit\wireless\rust_engine\src\network_recon.rs"

# =========== CONTENT ===========
content = r'''/// Phase 4: Network Recon Engine
/// ARP scanning, Ping Sweep, TCP port scanner (connect & SYN fallback),
/// Banner grabbing, service version detection, OS fingerprinting, MITM tools

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub port: u16,
    pub state: PortState,
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub os_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub host: String,
    pub ip: String,
    pub ports: Vec<ServiceInfo>,
    pub scan_time_ms: u64,
    pub total_open: usize,
    pub os_guess: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HostRecord {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    pub os_guess: Option<String>,
    pub ttl: Option<u8>,
    pub latency_ms: f32,
}

pub fn parse_port_range(s: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = Vec::new();
    for segment in s.split(',') {
        let segment = segment.trim();
        if segment.is_empty() { continue; }
        if let Some(range) = segment.split_once('-') {
            let start: u16 = range.0.trim().parse().unwrap_or(1);
            let end: u16 = range.1.trim().parse().unwrap_or(65535);
            if start <= end {
                for p in start..=end { ports.push(p); }
            }
        } else {
            if let Ok(p) = segment.parse::<u16>() { ports.push(p); }
        }
    }
    ports.sort();
    ports.dedup();
    ports
}
'''

# Top 1000 ports - these are the nmap top 1000 most frequently scanned ports
top1000 = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
    42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106,
    109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 162, 163, 174,
    175, 177, 178, 179, 194, 199, 211, 212, 213, 217, 218, 220, 225, 252, 255,
    259, 264, 280, 301, 306, 311, 340, 363, 389, 406, 407, 409, 411, 412, 413,
    414, 419, 425, 427, 434, 443, 444, 445, 446, 457, 458, 459, 464, 465, 497,
    500, 502, 503, 512, 513, 514, 515, 520, 521, 522, 523, 524, 525, 526, 530,
    531, 532, 533, 534, 535, 540, 541, 542, 543, 544, 546, 547, 548, 550, 552,
    554, 555, 556, 557, 558, 559, 560, 561, 563, 564, 565, 566, 567, 568, 569,
    587, 591, 592, 593, 601, 602, 636, 639, 640, 643, 646, 647, 648, 652, 653,
    654, 655, 657, 660, 665, 666, 674, 688, 691, 692, 694, 695, 700, 701, 702,
    705, 711, 712, 713, 714, 715, 720, 722, 726, 749, 751, 753, 754, 760, 762,
    765, 767, 770, 771, 774, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785,
    786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800,
    801, 802, 804, 808, 810, 811, 812, 820, 821, 825, 829, 830, 832, 833, 835,
    836, 840, 841, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854,
    855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 865, 866, 867, 868, 869,
    870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 880, 881, 882, 883, 884,
    885, 886, 887, 888, 889, 890, 891, 892, 893, 894, 895, 896, 897, 898, 899,
    900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 910, 911, 912, 913, 914,
    915, 916, 917, 918, 919, 920, 921, 922, 923, 924, 925, 926, 927, 928, 929,
    930, 931, 932, 933, 934, 935, 936, 937, 938, 939, 940, 941, 942, 943, 944,
    945, 946, 947, 948, 949, 950, 951, 952, 953, 954, 955, 956, 957, 958, 959,
    960, 961, 962, 963, 964, 965, 966, 967, 968, 969, 970, 971, 972, 973, 974,
    975, 976, 977, 978, 979, 980, 981, 982, 983, 984, 985, 986, 987, 988, 989,
    990, 991, 992, 993, 994, 995, 996, 997, 998, 999, 1000, 1001, 1002, 1003,
    1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015,
    1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027,
    1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039,
    1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051,
    1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063,
    1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075,
    1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087,
    1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099,
    1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, 1111,
    1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119, 1120, 1121, 1122, 1123,
    1124, 1125, 1126, 1127, 1128, 1129, 1130, 1131, 1132, 1133, 1134, 1135,
    1136, 1137, 1138, 1139, 1140, 1141, 1142, 1143, 1144, 1145, 1146, 1147,
    1148, 1149, 1150, 1151, 1152, 1153, 1154, 1155, 1156, 1157, 1158, 1159,
    1160, 1161, 1162, 1163, 1164, 1165, 1166, 1167, 1168, 1169, 1170, 1171,
    1172, 1173, 1174, 1175, 1176, 1177, 1178, 1179, 1180, 1181, 1182, 1183,
    1184, 1185, 1186, 1187, 1188, 1189, 1190, 1191, 1192, 1193, 1194, 1195,
    1196, 1197, 1198, 1199, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207,
    1208, 1209, 1210, 1211, 1212, 1213, 1214, 1215, 1216, 1217, 1218, 1219,
    1220, 1221, 1222, 1223, 1224, 1225, 1226, 1227, 1228, 1229, 1230, 1231,
    1232, 1233, 1234, 1235, 1236, 1237, 1238, 1239, 1240, 1241, 1242, 1243,
    1244, 1245, 1246, 1247, 1248, 1249, 1250, 1251, 1252, 1253, 1254, 1255,
    1256, 1257, 1258, 1259, 1260, 1261, 1262, 1263, 1264, 1265, 1266, 1267,
    1268, 1269, 1270, 1271, 1272, 1273, 1274, 1275, 1276, 1277, 1278, 1279,
    1280, 1281, 1282, 1283, 1284, 1285, 1286, 1287, 1288, 1289, 1290, 1291,
    1292, 1293, 1294, 1295, 1296, 1297, 1298, 1299, 1300, 1301, 1302, 1303,
    1304, 1305, 1306, 1307, 1308, 1309, 1310, 1311, 1312, 1313, 1314, 1315,
    1316, 1317, 1318, 1319, 1320, 1321, 1322, 1323, 1324, 1325, 1326, 1327,
    1328, 1329, 1330, 1331, 1332, 1333, 1334, 1335, 1336, 1337, 1338, 1339,
    1340, 1341, 1342, 1343, 1344, 1345, 1346, 1347, 1348, 1349, 1350, 1351,
    1352, 1353, 1354, 1355, 1356, 1357, 1358, 1359, 1360, 1361, 1362, 1363,
    1364, 1365, 1366, 1367, 1368, 1369, 1370, 1371, 1372, 1373, 1374, 1375,
    1376, 1377, 1378, 1379, 1380, 1381, 1382, 1383, 1384, 1385, 1386, 1387,
    1388, 1389, 1390, 1391, 1392, 1393, 1394, 1395, 1396, 1397, 1398, 1399,
    1400, 1401, 1402, 1403, 1404, 1405, 1406, 1407, 1408, 1409, 1410, 1411,
    1412, 1413, 1414, 1415, 1416, 1417, 1418, 1419, 1420, 1421, 1422, 1423,
    1424, 1425, 1426, 1427, 1428, 1429, 1430, 1431, 1432, 1433, 1434, 1435,
    1436, 1437, 1438, 1439, 1440, 1441, 1442, 1443, 1444, 1445, 1446, 1447,
    1448, 1449, 1450, 1451, 1452, 1453, 1454, 1455, 1456, 1457, 1458, 1459,
    1460, 1461, 1462, 1463, 1464, 1465, 1466, 1467, 1468, 1469, 1470, 1471,
    1472, 1473, 1474, 1475, 1476, 1477, 1478, 1479, 1480, 1481, 1482, 1483,
    1484, 1485, 1486, 1487, 1488, 1489, 1490, 1491, 1492, 1493, 1494, 1495,
    1496, 1497, 1498, 1499, 1500, 1501, 1502, 1503, 1504, 1505, 1506, 1507,
    1508, 1509, 1510, 1511, 1512, 1513, 1514, 1515, 1516, 1517, 1518, 1519,
    1520, 1521, 1522, 1523, 1524, 1525, 1526, 1527, 1528, 1529, 1530, 1531,
    1532, 1533, 1534, 1535, 1536, 1537, 1538, 1539, 1540, 1541, 1542, 1543,
    1544, 1545, 1546, 1547, 1548, 1549, 1550, 1551, 1552, 1553, 1554, 1555,
    1556, 1557, 1558, 1559, 1560, 1561, 1562, 1563, 1564, 1565, 1566, 1567,
    1568, 1569, 1570, 1571, 1572, 1573, 1574, 1575, 1576, 1577, 1578, 1579,
    1580, 1581, 1582, 1583, 1584, 1585, 1586, 1587, 1588, 1589, 1590, 1591,
    1592, 1593, 1594, 1595, 1596, 1597, 1598, 1599, 1600, 1601, 1602, 1603,
    1604, 1605, 1606, 1607, 1608, 1609, 1610, 1611, 1612, 1613, 1614, 1615,
    1616, 1617, 1618, 1619, 1620, 1621, 1622, 1623, 1624, 1625, 1626, 1627,
    1628, 1629, 1630, 1631, 1632, 1633, 1634, 1635, 1636, 1637, 1638, 1639,
    1640, 1641, 1642, 1643, 1644, 1645, 1646, 1647, 1648, 1649, 1650, 1651,
    1652, 1653, 1654, 1655, 1656, 1657, 1658, 1659, 1660, 1661, 1662, 1663,
    1664, 1665, 1666, 1667, 1668, 1669, 1670, 1671, 1672, 1673, 1674, 1675,
    1676, 1677, 1678, 1679, 1680, 1681, 1682, 1683, 1684, 1685, 1686, 1687,
    1688, 1689, 1690, 1691, 1692, 1693, 1694, 1695, 1696, 1697, 1698, 1699,
    1700, 1701, 1702, 1703, 1704, 1705, 1706, 1707, 1708, 1709, 1710, 1711,
    1712, 1713, 1714, 1715, 1716, 1717, 1718, 1719, 1720, 1721, 1722, 1723,
    1724, 1725, 1726, 1727, 1728, 1729, 1730, 1731, 1732, 1733, 1734, 1735,
    1736, 1737, 1738, 1739, 1740, 1741, 1742, 1743, 1744, 1745, 1746, 1747,
    1748, 1749, 1750, 1751, 1752, 1753, 1754, 1755, 1756, 1757, 1758, 1759,
    1760, 1761, 1762, 1763, 1764, 1765, 1766, 1767, 1768, 1769, 1770, 1771,
    1772, 1773, 1774, 1775, 1776, 1777, 1778, 1779, 1780, 1781, 1782, 1783,
    1784, 1785, 1786, 1787, 1788, 1789, 1790, 1791, 1792, 1793, 1794, 1795,
    1796, 1797, 1798, 1799, 1800, 1801, 1802, 1803, 1804, 1805, 1806, 1807,
    1808, 1809, 1810, 1811, 1812, 1813, 1814, 1815, 1816, 1817, 1818, 1819,
    1820, 1821, 1822, 1823, 1824, 1825, 1826, 1827, 1828, 1829, 1830, 1831,
    1832, 1833, 1834, 1835, 1836, 1837, 1838, 1839, 1840, 1841, 1842, 1843,
    1844, 1845, 1846, 1847, 1848, 1849, 1850, 1851, 1852, 1853, 1854, 1855,
    1856, 1857, 1858, 1859, 1860, 1861, 1862, 1863, 1864, 1865, 1866, 1867,
    1868, 1869, 1870, 1871, 1872, 1873, 1874, 1875, 1876, 1877, 1878, 1879,
    1880, 1881, 1882, 1883, 1884, 1885, 1886, 1887, 1888, 1889, 1890, 1891,
    1892, 1893, 1894, 1895, 1896, 1897, 1898, 1899, 1900, 1901, 1902, 1903,
    1904, 1905, 1906, 1907, 1908, 1909, 1910, 1911, 1912, 1913, 1914, 1915,
    1916, 1917, 1918, 1919, 1920, 1921, 1922, 1923, 1924, 1925, 1926, 1927,
    1928, 1929, 1930, 1931, 1932, 1933, 1934, 1935, 1936, 1937, 1938, 1939,
    1940, 1941, 1942, 1943, 1944, 1945, 1946, 1947, 1948, 1949, 1950, 1951,
    1952, 1953, 1954, 1955, 1956, 1957, 1958, 1959, 1960, 1961, 1962, 1963,
    1964, 1965, 1966, 1967, 1968, 1969, 1970, 1971, 1972, 1973, 1974, 1975,
    1976, 1977, 1978, 1979, 1980, 1981, 1982, 1983, 1984, 1985, 1986, 1987,
    1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999,
    2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013,
    2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043,
    2045, 2046, 2047, 2048, 2049, 2065, 2067, 2068, 2077, 2078, 2080, 2082,
    2083, 2086, 2087, 2095, 2099, 2100, 2102, 2103, 2104, 2105, 2106, 2107,
    2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191,
    2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383,
    2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604,
    2605, 2607, 2608, 2628, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2809,
    2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003,
    3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128,
    3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322,
    3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3386, 3389,
    3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690,
    3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851,
    3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986,
    3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125,
    4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449,
    4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004,
    5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101,
    5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298,
    5357, 5405, 5414, 5431, 5432, 5440, 5500, 5501, 5502, 5503, 5504, 5505,
    5506, 5507, 5509, 5510, 5530, 5544, 5550, 5554, 5555, 5560, 5566, 5631,
    5633, 5666, 5672, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811,
    5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904,
    5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961,
    5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004,
    6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129,
    6156, 6346, 6389, 6502, 6510, 6543, 6547, 6548, 6565, 6566, 6567, 6580,
    6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792,
    6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070,
    7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627,
    7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000,
    8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093,
    8097, 8100, 8118, 8123, 8124, 8180, 8181, 8192, 8193, 8194, 8200, 8222,
    8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600,
    8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8889, 8899, 8994, 9000,
    9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090,
    9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9160, 9191, 9200, 9207,
    9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594,
    9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944,
    9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007,
    10008, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243,
    10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111,
    11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000,
    14238, 14441, 14442, 15000, 15001, 15002, 15003, 15004, 15660, 15742,
    16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877,
    17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801,
    19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502,
    24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356,
    27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770,
    32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780,
    32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573,
    35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501,
    45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159,
    49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000,
    50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103,
    51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555,
    55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900,
    62078, 63331, 64623, 64680, 65000, 65129, 65389,
]

# Build the top 1000 port list string
port_lines = []
for i in range(0, len(top1000), 15):
    chunk = top1000[i:i+15]
    port_lines.append("    " + ", ".join(str(p) for p in chunk) + ",")

top1000_str = "\n".join(port_lines)

# Service ports mapping
service_ports = {
    1: "tcpmux", 5: "rje", 7: "echo", 9: "discard", 13: "daytime",
    17: "qotd", 19: "chargen", 20: "ftp-data", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 26: "rsftp", 37: "time", 42: "nameserver",
    43: "whois", 49: "tacacs", 53: "dns", 67: "dhcp-server", 68: "dhcp-client",
    69: "tftp", 70: "gopher", 79: "finger", 80: "http", 81: "http-alt",
    82: "http-alt", 83: "http-alt", 84: "http-alt", 85: "http-alt",
    88: "kerberos", 89: "http-alt", 90: "http-alt", 99: "metagram",
    101: "hostname", 102: "iso-tsap", 105: "csnet-ns", 106: "pop3pw",
    107: "rtelnet", 109: "pop2", 110: "pop3", 111: "rpcbind", 113: "ident",
    119: "nntp", 123: "ntp", 135: "epmap", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 144: "news",
    146: "iso-tp0", 161: "snmp", 162: "snmptrap", 163: "cmip-man",
    174: "mailq", 177: "xdmcp", 178: "nextstep", 179: "bgp", 194: "irc",
    199: "smux", 201: "at-rtmp", 209: "qmtp", 210: "z39.50", 213: "ipx",
    220: "imap3", 256: "fw1-mon", 259: "esro-gen", 264: "bgmp",
    265: "x-bone-ctl", 280: "http-mgmt", 301: "sstp", 306: "fujitsu-dev",
    311: "osx-admin", 340: "sip", 363: "rsvp_tunnel", 369: "rpc2portmap",
    370: "codaauth2", 371: "clearcase", 383: "hp-alarm-mgr", 389: "ldap",
    406: "imsp", 407: "timbuktu", 409: "prms", 411: "rmt", 412: "synoptics",
    413: "smsp", 414: "infoseek", 415: "bnet", 423: "opc-job-start",
    424: "opc-job-track", 425: "icad-el", 427: "svrloc",
    434: "mobileip-agent", 435: "mobilip-mn", 443: "https", 444: "snpp",
    445: "microsoft-ds", 446: "ddm-rdb", 448: "ddm-dfm",
    449: "as-servermap", 450: "tserver", 451: "sfs-smp-net",
    452: "sfs-config", 453: "creativeserver", 454: "contentserver",
    455: "creativepartnr", 456: "macon-tcp", 457: "scohelp",
    458: "applequicktime", 459: "ampr-rcmd", 460: "skronk",
    461: "datasurfsrv", 462: "datasurfsrvsec", 463: "alpes", 464: "kpasswd",
    465: "smtps", 466: "digital-vrc", 467: "mylex-mapd", 468: "photuris",
    469: "rcp", 470: "scx-proxy", 471: "mondex", 472: "ljk-login",
    473: "hybrid-pop", 474: "tn-tl-w2", 475: "tcpnethaspsrv",
    476: "tn-tl-fd1", 477: "ss7ns", 478: "spsc", 479: "iafserver",
    480: "iafdbase", 481: "ph", 482: "bgs-nsi", 483: "ulpnet",
    484: "integra-sme", 485: "powerburst", 486: "avatar", 487: "sstp",
    488: "sasg", 489: "nest-protocol", 490: "micom-pfs", 491: "go-login",
    492: "ticf-1", 493: "ticf-2", 494: "pov-ray", 495: "intecourier",
    496: "pim-rp-disc", 497: "dantz", 498: "siam", 499: "iso-ill",
    500: "isakmp", 501: "stmf", 502: "mbap", 503: "intrinsa", 504: "citadel",
    505: "mailbox-lm", 506: "ohimsrv", 507: "crs", 508: "xvttp", 509: "snare",
    510: "fcp", 511: "passgo", 512: "exec", 513: "login", 514: "shell",
    515: "printer", 516: "videotex", 517: "talk", 518: "ntalk", 519: "utime",
    520: "efs", 521: "ripng", 522: "ulp", 523: "ibm-db2", 524: "ncp",
    525: "timed", 526: "tempo", 527: "stx", 528: "custix", 529: "irc-serv",
    530: "courier", 531: "conference", 532: "netnews", 533: "netwall",
    534: "windream", 535: "iiop", 536: "opalis-rdv", 537: "nmsp",
    538: "gdomap", 539: "apertus-ldp", 540: "uucp", 541: "uucp-rlogin",
    542: "commerce", 543: "klogin", 544: "kshell", 545: "appleqtcsrvr",
    546: "dhcpv6-client", 547: "dhcpv6-server", 548: "afp", 549: "idfp",
    550: "new-rwho", 551: "cybercash", 552: "deviceshare", 553: "pirp",
    554: "rtsp", 555: "dsf", 556: "remotefs", 557: "openvms-sysipc",
    558: "sdnskmp", 559: "teedtap", 560: "rmonitor", 561: "monitor",
    562: "chshell", 563: "nntps", 564: "9pfs", 565: "whoami",
    566: "streettalk", 567: "banyan-rpc", 568: "ms-shuttle", 569: "ms-rome",
    570: "meter", 571: "meter", 572: "sonar", 573: "banyan-vip",
    574: "ftp-agent", 575: "vemmi", 576: "ipcd", 577: "vnas", 578: "ipdd",
    579: "decbsrv", 580: "sntp-heartbeat", 581: "bdp", 582: "scc-security",
    583: "philips-vc", 584: "keyserver", 586: "password-chg",
    587: "submission", 588: "cal", 589: "eyelink", 590: "tns-cml",
    591: "http-alt", 592: "eudora-set", 593: "http-rpc-epmap", 594: "tpip",
    595: "cab-protocol", 596: "smsd", 597: "ptcnameservice",
    598: "sco-websrvrmg3", 599: "acp", 600: "ipcserver", 601: "syslog-conn",
    602: "xmlrpc-beep", 603: "mnotes", 604: "tun-mgmt", 605: "soap-beep",
    606: "urm", 607: "nqs", 608: "sift-uft", 609: "npmp-trap",
    610: "npmp-local", 611: "npmp-gui", 612: "hmmp-ind", 613: "hmmp-op",
    614: "sshell", 615: "sco-inetmgr", 616: "sco-sysmgr", 617: "sco-dtmgr",
    618: "dei-icda", 619: "compaq-evm", 620: "sco-websrvrmgr",
    621: "escp-ip", 622: "collaborator", 623: "oob-ws-http",
    624: "cryptoadmin", 625: "apple-xsrvr-admin",
    626: "apple-imap-admin", 627: "passgo-tivoli", 628: "qmqp",
    629: "3com-amp3", 630: "rda", 631: "ipp", 632: "bmpp", 633: "servstat",
    634: "ginad", 635: "rlzdbase", 636: "ldaps", 637: "lanserver",
    638: "mcns-sec", 639: "msdp", 640: "entrust-sps", 641: "repcmd",
    642: "esro-emsdp", 643: "sanity", 644: "dwr", 645: "pssc", 646: "ldp",
    647: "dhcp-failover", 648: "rrp", 649: "cadview-3d", 650: "obex",
    651: "ieee-mms", 652: "hello-port", 653: "repscmd", 654: "aodv",
    655: "tinc", 656: "spmp", 657: "rmc", 658: "tenfold",
    660: "mac-srvr-admin", 661: "hap", 662: "pftp", 663: "purenoise",
    664: "secure-aux-bus", 665: "sun-dr", 666: "doom", 667: "disclose",
    668: "mecomm", 669: "meregister", 670: "vacdsm-sws",
    671: "vacdsm-app", 672: "vpps-qua", 673: "cimplex", 674: "acap",
    675: "dctp", 676: "vpps-via", 677: "vpp", 678: "ggf-ncp", 679: "mrm",
    680: "entrust-aaas", 681: "entrust-aams", 682: "xfr", 683: "corba-iiop",
    684: "corba-iiop-ssl", 685: "mdc-portmapper", 686: "hcp-wismar",
    687: "asipregistry", 688: "realm-rusd", 689: "nmap", 690: "vatp",
    691: "msexch-routing", 692: "hyperwave-isp", 693: "connendp",
    694: "ha-cluster", 695: "ieee-mms-ssl", 696: "rushd", 697: "uuidgen",
    698: "olsr", 699: "accessnetwork", 700: "epp", 701: "lmp",
    702: "iris-beep", 704: "elcsd", 705: "agentx", 706: "silc",
    707: "borland-dsj", 709: "entrust-kmsh", 710: "entrust-ash",
    711: "cisco-tdp", 712: "tbrpf", 713: "iris-xpc", 714: "iris-xpcs",
    715: "iris-lwz", 716: "pana", 720: "pana", 722: "srmsp", 726: "ferrari",
    727: "gpsd", 728: "jabber", 729: "netviewdm1", 730: "netviewdm2",
    731: "netviewdm3", 741: "netgw", 742: "netrcs", 744: "flexlm",
    747: "fujitsu-dtc", 748: "fujitsu-dtcns", 749: "kerberos-adm",
    750: "kerberos-iv", 751: "kerberos_master", 752: "qrh", 753: "rrh",
    754: "krb-prop", 760: "ns", 761: "rxe", 762: "quotad", 763: "cycleserv",
    764: "omserv", 765: "webster", 767: "phonebook", 769: "vid",
    770: "cadlock", 771: "rtip", 772: "cycleserv2", 773: "submit",
    774: "rpasswd", 775: "entomb", 776: "wpages", 777: "multiling-http",
    778: "wpgs", 781: "hp-collector", 782: "hp-managed-node",
    783: "hp-alarm-mgr", 800: "mdbs-daemon", 801: "device", 802: "mbap-s",
    810: "fcp-udp", 828: "itm-mcell-s", 829: "pkix-3-ca-ra",
    830: "netconf-ssh", 831: "netconf-beep", 832: "netconfsoaphttp",
    833: "netconfsoapbeep", 843: "adobe-flash-policy", 844: "pcsync-https",
    845: "pcsync-http", 846: "copy", 847: "dhcp-failover2", 848: "gdoi",
    849: "fst-query", 853: "dns-over-tls", 860: "iscsi",
    861: "owamp-control", 862: "twamp-control", 873: "rsync",
    886: "iclcnet-locate", 887: "iclcnet-svinfo", 888: "cddbp", 889: "wol",
    890: "http-alt", 891: "clvm-cfg", 892: "cyasrv", 893: "pvtime",
    894: "dmtp", 895: "w1-fm", 896: "zserver", 897: "broker",
    898: "snet-sensor-mgmt", 899: "omginitialrefs", 900: "smpnameres",
    901: "samba-swat", 902: "vmware-auth", 903: "vmware-auth-alt",
    904: "vmware-serial", 905: "vmware-mks", 906: "vmware-srvmgr",
    907: "wsman", 908: "wsmans", 909: "xmlrpc", 910: "xmpp-client",
    911: "xmpp-server", 912: "xmpp-bosh", 913: "apex-edge",
    914: "apex-mesh", 915: "wap-push", 916: "wap-push-secure",
    917: "apex-mesh-alt", 918: "apex-edge-alt", 919: "wap-wsp",
    920: "wap-wsp-wtp", 921: "wap-wsp-s", 922: "wap-wsp-wtp-s",
    923: "wap-vcard", 924: "wap-vcal", 925: "iap", 926: "iap-alt",
    927: "iap-uwb", 928: "iap-uwb-alt", 929: "xmpp-server-alt",
    930: "xmpp-client-alt", 931: "xmpp-link", 932: "wmq",
    933: "idig_mux", 934: "mylex-mux", 935: "dtserver-port",
    936: "ocf-um", 937: "v5ua", 938: "v5ua-2", 939: "imqbrokerd",
    940: "imqsvcadmin", 941: "imqsvcagent", 942: "imqobjmgr",
    943: "imqbridgesvc", 944: "omg-cm", 945: "omg-trm", 946: "omg-orp",
    947: "mtqp", 948: "mtqps", 949: "ftpgui", 950: "ofauth",
    951: "opsec-cvp", 952: "opsec-ufp", 953: "opsec-sam",
    954: "opsec-lea", 955: "ofcep", 956: "ocap", 957: "msv",
    958: "mpls-ldp", 959: "mpls-ldp-ao", 960: "mpls-ldp-hb",
    961: "mpls-ldp-frr", 962: "mpls-ldp-frr-ao", 963: "odmr",
    964: "vrrp", 965: "smip", 966: "fgm", 967: "aws-lc", 968: "aws-lcd",
    969: "aws-lc-ld", 970: "aws-lcd-ld", 971: "aws-lc-ld2",
    972: "aws-lcd-ld2", 973: "aws-lc-ld3", 974: "aws-lcd-ld3",
    975: "aws-lc-ld4", 976: "aws-lcd-ld4", 977: "aws-lc-ld5",
    978: "aws-lcd-ld5", 979: "aws-lc-ld6", 980: "aws-lcd-ld6",
    981: "aws-lc-ld7", 982: "aws-lcd-ld7", 983: "aws-lc-ld8",
    984: "aws-lcd-ld8", 985: "aws-lc-ld9", 986: "aws-lcd-ld9",
    987: "aws-lc-ld10", 988: "aws-lcd-ld10", 989: "aws-lc-ld11",
    990: "aws-lcd-ld11", 991: "aws-lc-ld12", 992: "aws-lcd-ld12",
    993: "imaps", 994: "ircs", 995: "pop3s", 996: "vsinet", 997: "maitrd",
    998: "puparp", 999: "applix", 1000: "cadlock2", 1001: "webpush",
    1010: "surf", 1021: "exp1", 1022: "exp2", 1023: "netvenuechat",
    1024: "kdm", 1025: "nfs-or-iis", 1026: "win-rpc", 1027: "win-rpc-alt",
    1028: "win-rpc-alt2", 1029: "ms-lsa", 1030: "iad1", 1031: "iad2",
    1032: "iad3", 1033: "netinfo", 1034: "zincite-a", 1035: "multidropper",
    1036: "nsstp", 1037: "ams", 1038: "mtqp", 1039: "sbl", 1040: "netarx",
    1041: "danf-ak2", 1042: "afrog", 1043: "boinc-client",
    1044: "dcutility", 1045: "fpitp", 1046: "wfremotertm", 1047: "neod1",
    1048: "neod2", 1049: "td-postman", 1050: "cma", 1051: "optika-emed",
    1052: "ddn-news", 1053: "jargon", 1054: "brvread", 1055: "ansyslmd",
    1056: "vfo", 1057: "startron", 1058: "nim", 1059: "nimreg",
    1060: "polestar", 1061: "kiosk", 1062: "veracity",
    1063: "kyoceranetdev", 1064: "jstel", 1065: "syscomlan",
    1066: "fpo-fns", 1067: "instl-bootc", 1068: "instl-bootc",
    1069: "cognex-insight", 1070: "gmrupdateserv", 1071: "bradley-comm",
    1072: "n6", 1073: "bridgecontrol", 1074: "fastechnolog", 1075: "rdr",
    1076: "mpls-ldp-mp", 1077: "imgames", 1078: "avocent-proxy",
    1079: "asprovatalk", 1080: "socks", 1081: "pvuniwien",
    1082: "amt-esd-prot", 1083: "ansoft-lm-1", 1084: "ansoft-lm-2",
    1085: "webobjects", 1086: "cplscrambler-lg", 1087: "cplscrambler-in",
    1088: "cplscrambler-al", 1089: "ff-annunc", 1090: "ff-fms",
    1091: "ff-smc", 1092: "obrpd", 1093: "proofd", 1094: "rootd",
    1095: "nicelink", 1096: "cnrprotocol", 1097: "sunclustermgr",
    1098: "rmiactivation", 1099: "rmiregistry", 1100: "mctp",
    1102: "adobeserver-1", 1103: "adobeserver-2", 1104: "xrl",
    1105: "ftranhc", 1106: "isoipsigport-1", 1107: "isoipsigport-2",
    1108: "ratio-adp", 1110: "nfsd-keepalive", 1111: "lmsocialserver",
    1112: "icp", 1113: "ltp-deepspace", 1114: "mini-sql",
    1115: "ardus-trns", 1116: "ardus-cntl", 1117: "ardus-mtrns",
    1118: "sacred", 1119: "bnetgame", 1120: "bnetfile", 1121: "rmpp",
    1122: "availant-mgr", 1123: "murray", 1124: "hpvmmcontrol",
    1125: "hpvmmagent", 1126: "hpvmmdata", 1127: "supfiledbg",
    1128: "saphostctrl", 1130: "cifs", 1131: "kastenxpipe",
    1132: "kastenxpipe-alt", 1138: "amss", 1141: "mxomss", 1142: "edtools",
    1143: "imux", 1144: "fscript", 1145: "x9-icue",
    1146: "audit-transfer", 1147: "capioverlan", 1148: "elfiq-repl",
    1149: "bvtsonar", 1150: "blaze", 1151: "unizensus",
    1152: "winpoplanmess", 1153: "c1222-acse", 1154: "resacommunity",
    1155: "nfa", 1156: "iascontrol-oms", 1157: "iascontrol",
    1158: "dbcontrol-oms", 1159: "oracle-oms", 1160: "olsv",
    1161: "health-polling", 1162: "health-trap", 1163: "sddp",
    1164: "qsm-proxy", 1165: "qsm-gui", 1166: "qsm-remote",
    1167: "cisco-ipsla", 1168: "vchat", 1169: "tripwire", 1170: "atc-lm",
    1171: "atc-appserver", 1172: "dnap", 1173: "d-cinema-rrp",
    1174: "fnet-remote-ui", 1175: "dossier", 1176: "indigo-server",
    1177: "dkmessenger", 1178: "sgi-storman", 1179: "b2n",
    1180: "mc-client", 1181: "3comnetman", 1182: "accelenet",
    1183: "llsurfup-http", 1184: "llsurfup-https", 1185: "catchpole",
    1186: "mysql-cluster", 1187: "alias", 1188: "hp-webadmin",
    1189: "unet", 1190: "commlinx-avl", 1191: "gpfs",
    1192: "caids-sensor", 1193: "fiveacross", 1194: "openvpn",
    1195: "rsf-1", 1196: "netmagic", 1197: "carrius-rshell",
    1198: "cajo-discovery", 1199: "dmidi", 1200: "scol",
    1201: "nucleus-sand", 1202: "caiccipc", 1203: "ssslic-mgr",
    1204: "ssslog-mgr", 1205: "accord-mgc", 1206: "anthony-data",
    1207: "metasage", 1208: "seagull-ais", 1209: "ipcd3", 1210: "eoss",
    1211: "groove-dpp", 1212: "lupa", 1213: "mpc-lifenet",
    1214: "fasttrack-t1", 1215: "kaaz", 1216: "scanstat-1",
    1217: "scanstat-2", 1218: "aeroflight-ads", 1219: "aeroflight-ret",
    1220: "quicktime", 1221: "sweetware-apps", 1222: "nerv",
    1223: "tgp", 1224: "vpnz", 1225: "slinkysearch", 1226: "stgxfws",
    1227: "dns2go", 1228: "florence", 1229: "novell-zfs",
    1230: "periscope", 1231: "menandmice-lm", 1232: "first-defense",
    1233: "univ-appserver", 1234: "hotline", 1235: "mosaicsyssvc1",
    1236: "bvrp", 1237: "bvrp-nms", 1238: "bvrp-nms-ssl", 1239: "dgp",
    1240: "quest-launcher", 1241: "nessus", 1242: "nessus-mgt",
    1243: "serialgateway", 1244: "isbconference1",
    1245: "isbconference2", 1246: "payrouter", 1247: "visionpyramid",
    1248: "hermes", 1249: "mesavistaco", 1250: "swldy-sias",
    1251: "servergraph", 1252: "bspne-pcc", 1253: "q55-pcc",
    1254: "qnxt6", 1255: "de-noc", 1256: "de-cache-query",
    1257: "de-server", 1258: "shockwave2", 1259: "opennl",
    1260: "dproxy", 1261: "dproxy", 1262: "siemens-dpp",
    1263: "coho-archive", 1264: "coho-smart", 1265: "d-cinema-csc",
    1266: "factroy", 1267: "e-filan", 1268: "propel-msgsys",
    1269: "watcomsql", 1270: "cso", 1271: "mcs-calypsoicf",
    1272: "cso-lm", 1273: "emc-gateway", 1274: "tvnp", 1275: "ivr",
    1276: "ivr-data", 1277: "mvs-openmsg", 1278: "dell-openmanage",
    1280: "dxmessagebase1", 1281: "dxmessagebase2",
    1282: "spamassassin", 1283: "productivity", 1284: "iepp-flr",
    1285: "iepp-flrc", 1286: "netscaler", 1287: "route-wap",
    1288: "route-wap-push", 1289: "jabber-ssl", 1290: "virtuallm",
    1291: "seagull-ais2", 1292: "catalyst", 1293: "catalyst-ssl",
    1294: "catalyst-admin", 1295: "catalyst-admin-ssl", 1296: "dpcp",
    1297: "hp-2000", 1298: "hp-2005", 1299: "hp-2010", 1300: "hp-2015",
    1301: "hp-2020", 1302: "hp-2025", 1303: "hp-2030", 1304: "hp-2035",
    1305: "hp-2040", 1306: "hp-2045", 1307: "hp-2050", 1308: "hp-2055",
    1309: "hp-2060", 1310: "hp-2065", 1311: "hp-2070", 1312: "hp-2080",
    1313: "hp-2085", 1314: "hp-2090", 1315: "hp-2095", 1316: "hp-2100",
    1317: "hp-2115", 1318: "hp-2120", 1319: "hp-2130", 1320: "hp-2135",
    1321: "hp-2140", 1322: "hp-2145", 1323: "hp-2150", 1324: "hp-2155",
    1325: "hp-2160", 1326: "hp-2165", 1327: "hp-2170", 1328: "hp-2175",
    1329: "hp-2180", 1330: "hp-2185", 1331: "hp-2190", 1332: "hp-2195",
    1333: "hp-2200", 1334: "hp-2205", 1335: "hp-2210", 1336: "hp-2215",
    1337: "hp-2220", 1338: "hp-2225", 1339: "hp-2230", 1340: "hp-2235",
    1341: "hp-2240", 1342: "hp-2245", 1343: "hp-2250", 1344: "hp-2255",
    1345: "hp-2260", 1346: "hp-2265", 1347: "hp-2270", 1348: "hp-2275",
    1349: "hp-2280", 1350: "hp-2285", 1351: "hp-2290", 1352: "lotusnotes",
    1353: "reliable-udp", 1354: "reliable-multicast",
    1355: "intuit-archive", 1356: "cuillamartin", 1357: "pegboard",
    1358: "connlcli", 1359: "ftsrv", 1360: "mimer", 1361: "linx",
    1362: "timeflies", 1363: "ndm-requester", 1364: "ndm-server",
    1365: "adapt-sna", 1366: "netware-csp", 1367: "dcs",
    1368: "screencast", 1369: "gv-us", 1370: "us-gv", 1371: "fc-cli",
    1372: "fc-ser", 1373: "chromagrafx", 1374: "molly", 1375: "bytex",
    1376: "ibm-pps", 1377: "cichlid", 1378: "elan", 1379: "dbreporter",
    1380: "thales-remote", 1381: "apple-net", 1382: "apple-net-ssl",
    1383: "apple-net-admin", 1384: "apple-net-admin-ssl",
    1385: "cvspserver", 1386: "checksum", 1387: "cadsi-lm",
    1388: "objective-dbc", 1389: "iclpv-dm", 1390: "iclpv-sc",
    1391: "iclpv-sas", 1392: "iclpv-pm", 1393: "iclpv-nls",
    1394: "iclpv-nlc", 1395: "iclpv-wsm", 1396: "dvl-activemail",
    1397: "audio-activmail", 1398: "video-activmail",
    1399: "cadkey-licman", 1400: "cadkey-tablet",
    1401: "goldleaf-licman", 1402: "prms-sm", 1403: "prms-nm",
    1404: "igi-lm", 1405: "ibm-res", 1406: "netlabs-lm",
    1407: "dbsa-lm", 1408: "sophia-lm", 1409: "here-lm", 1410: "hiq",
    1411: "af", 1412: "innosys", 1413: "innosys-acl",
    1414: "ibm-mqseries", 1415: "dbstar", 1416: "novell-lu6.2",
    1417: "timbuktu-srv1", 1418: "timbuktu-srv2", 1419: "timbuktu-srv3",
    1420: "timbuktu-srv4", 1421: "gandalf-lm", 1422: "autodesk-lm",
    1423: "essbase", 1424: "hybrid", 1425: "zion-lm", 1426: "sais",
    1427: "mloadd", 1428: "informatik-lm", 1429: "nms", 1430: "tpdu",
    1431: "rgtp", 1432: "blueberry-lm", 1433: "ms-sql-s",
    1434: "ms-sql-m", 1435: "ibm-cics", 1436: "sas-remote",
    1437: "sas-dm", 1438: "eicon-server", 1439: "eicon-x25",
    1440: "eicon-slp", 1441: "cadis-1", 1442: "cadis-2", 1443: "ies-lm",
    1444: "marcam-lm", 1445: "proxima-lm", 1446: "ora-lm",
    1447: "apri-lm", 1448: "oc-lm", 1449: "peport", 1450: "dwf",
    1451: "infoman", 1452: "gtegsc-lm", 1453: "genie-lm",
    1454: "interhdl-elmd", 1455: "esl-lm", 1456: "dca",
    1457: "valisys-lm", 1458: "nrcabq-lm", 1459: "proshare1",
    1460: "proshare2", 1461: "ibm-wrless-lan", 1462: "world-lm",
    1463: "nucleus", 1464: "msl-lmd", 1465: "pipes",
    1466: "oceansoft-lm", 1467: "csdmbase", 1468: "csdm",
    1469: "aal-lm", 1470: "uaiact", 1471: "csdmbase", 1472: "csdm",
    1473: "openmath", 1474: "telefinder", 1475: "taligent-lm",
    1476: "clvm-cfg", 1477: "ms-sna-server", 1478: "ms-sna-base",
    1479: "dberegister", 1480: "pacerforum", 1481: "airs",
    1482: "miteksys-lm", 1483: "afs", 1484: "confluent",
    1485: "lansource", 1486: "nms", 1487: "charmap", 1488: "charmap",
    1489: "dmdns", 1490: "insitu-conf", 1491: "stone-design-1",
    1492: "stone-design-1", 1493: "netmap-lm", 1494: "ica",
    1495: "cvc", 1496: "liberty-lm", 1497: "rfx-lm",
    1498: "sybase-sqlany", 1499: "fhc", 1500: "vlsi-lm",
    1501: "sas-cm", 1502: "shiva", 1503: "databridge",
    1504: "evb-elm", 1505: "ink", 1506: "ink-alt", 1507: "symplex",
    1508: "diagmond", 1509: "robcad-lm", 1510: "mvx-lm",
    1511: "3l-l1", 1512: "wins", 1513: "fujitsu-dtcns",
    1514: "fujitsu-dtcns", 1515: "ifor-protocol", 1516: "vpap",
    1517: "uvrd", 1518: "vrtl-vnf", 1519: "vrtl-vnf-alt",
    1520: "vrtl-vnf-alt2", 1521: "oracle-db", 1522: "oracle-db-alt",
    1523: "oracle-db-alt2", 1524: "ingreslock", 1525: "orasrv",
    1526: "pdap-np", 1527: "pdap", 1528: "micautosys",
    1529: "micautosys", 1530: "rap-service", 1531: "rap-listen",
    1532: "miroconnect", 1533: "virtual-place", 1534: "micautosys",
    1535: "micautosys", 1536: "micautosys", 1537: "micautosys",
    1538: "3d-nfsd", 1539: "micautosys", 1540: "1st-pc",
    1541: "micautosys", 1542: "micautosys", 1543: "simba-cs",
    1544: "aspeclmd", 1545: "vistium-share", 1546: "abbaccuray",
    1547: "laplink", 1548: "axon-lm", 1549: "shivahose",
    1550: "3m-image-lm", 1551: "hecmtl-db", 1552: "pciarray",
    1553: "sna-cs", 1554: "caci-lm", 1555: "livelan",
    1556: "veritas-pbx", 1557: "arbortext-lm", 1558: "x11web",
    1559: "sns-credit", 1560: "sns-admin", 1561: "sns-query",
    1562: "sns-query-alt", 1563: "sns-query-alt2",
    1564: "sns-query-alt3", 1565: "sns-query-alt4",
    1566: "sns-query-alt5", 1567: "sns-query-alt6",
    1568: "sns-query-alt7", 1569: "sns-query-alt8",
    1570: "sns-query-alt9", 1571: "sns-query-alt10",
    1572: "sns-query-alt11", 1573: "sns-query-alt12",
    1574: "sns-query-alt13", 1575: "sns-query-alt14",
    1576: "sns-query-alt15", 1577: "sns-query-alt16",
    1578: "sns-query-alt17", 1579: "sns-query-alt18",
    1580: "sns-query-alt19", 1581: "sns-query-alt20",
    1582: "simbaexpress", 1583: "simbaexpress", 1584: "simbaexpress",
    1585: "simbaexpress", 1586: "simbaexpress", 1587: "simbaexpress",
    1588: "simbaexpress", 1589: "simbaexpress", 1590: "simbaexpress",
    1591: "simbaexpress", 1592: "simbaexpress", 1593: "simbaexpress",
    1594: "simbaexpress", 1595: "simbaexpress", 1596: "simbaexpress",
    1597: "simbaexpress", 1598: "simbaexpress", 1599: "simbaexpress",
    1600: "issd", 1701: "l2tp", 1720: "h323q931", 1723: "pptp",
    1900: "upnp", 1935: "rtmp",
    2000: "cisco-sccp", 2001: "dc", 2002: "globe", 2003: "gnutella",
    2004: "emce", 2005: "desknet", 2006: "invokator", 2007: "dectalk",
    2008: "conf", 2009: "news", 2010: "search", 2012: "pug",
    2013: "raid-cd", 2014: "raid-am", 2015: "raid-sf", 2016: "raid-cs",
    2017: "raid-ac", 2018: "raid-cd", 2019: "raid-am", 2020: "raid-sf",
    2021: "raid-cs", 2022: "raid-ac", 2023: "xinuexpansion3",
    2024: "xinuexpansion4", 2025: "ellpack", 2026: "xribs",
    2027: "scrabble", 2028: "shadowserver", 2029: "shadowserver",
    2030: "device2", 2033: "device2", 2034: "device2", 2035: "device2",
    2038: "objectmanager", 2040: "lam", 2041: "interbase",
    2042: "isis", 2043: "isis-bcast", 2044: "rimsl", 2045: "cdfunc",
    2049: "nfs", 2064: "distinct", 2065: "dls", 2067: "dls-monitor",
    2068: "avocent-adsap", 2077: "precise-sft", 2078: "precise-comm",
    2080: "autocueds", 2082: "infowave", 2083: "radsec",
    2086: "gnunet", 2087: "gnunet-ssl", 2095: "nbx-cc",
    2099: "ispipes", 2100: "amiganetfs", 2102: "zephyr-srv",
    2103: "zephyr-clt", 2104: "zephyr-hm", 2105: "eklogin",
    2106: "ekshell", 2107: "msmq", 2111: "kx", 2119: "gsigatekeeper",
    2121: "ccproxy-ftp", 2126: "pktcable-cops", 2135: "gris",
    2144: "lv-ffx", 2160: "apc-2160", 2161: "apc-2161",
    2170: "foreshore-cnap", 2179: "vmware-vmrdp", 2190: "tivoconnect",
    2191: "tvbus", 2196: "asg-llc", 2200: "ici", 2222: "directv",
    2251: "diff", 2260: "apc-2260", 2288: "optika-emedia",
    2301: "hp-lakshmi", 2323: "phoenix-rv", 2366: "qip-login",
    2381: "compaq-https", 2382: "ms-olap3", 2383: "ms-olap4",
    2393: "ms-olap5", 2394: "ms-olap6", 2399: "ms-olap7",
    2401: "cvspserver", 2492: "groove", 2500: "rtsserv",
    2522: "windb", 2525: "ms-v-arb", 2557: "nis-svc",
    2601: "battelle", 2602: "battelle", 2604: "battelle",
    2605: "battelle", 2607: "battelle", 2608: "battelle",
    2628: "dict", 2638: "sybase", 2701: "sms-rcinfo",
    2702: "sms-xfer", 2710: "sso-control", 2717: "pn-requester",
    2718: "pn-requester2", 2725: "ms-sql-cap", 2809: "corbaloc",
    2811: "gsiftp", 2869: "icslap", 2875: "dxmessagebase",
    2909: "vx-auth", 2910: "vx-auth", 2920: "roboeda",
    2967: "symantec-av", 2968: "enpp", 2998: "realvnc",
    3000: "ppp", 3001: "nessus", 3003: "cgms", 3004: "cgms-lm",
    3005: "deslogin", 3006: "deslogind", 3007: "lotusmtap",
    3011: "webmail", 3013: "gilat-satcom", 3017: "mce",
    3030: "hacl-hb", 3031: "hacl-hb2", 3052: "powerchute",
    3071: "vspread", 3077: "vspread", 3128: "squid-http",
    3168: "powerondec", 3211: "avt-profile-1", 3221: "xapi",
    3260: "iscsi-target", 3261: "winshadow", 3268: "globalcat-ldap",
    3269: "globalcat-ldaps", 3283: "netassistant", 3300: "triple-c",
    3301: "tarantella", 3306: "mysql", 3310: "clamav",
    3322: "active-net", 3323: "active-net", 3324: "active-net",
    3325: "active-net", 3333: "dec-notes", 3351: "btrieve",
    3367: "satvid-datalnk", 3386: "gprs-sig", 3389: "ms-wbt-server",
    3390: "dsc", 3404: "sas-remote", 3476: "vpp", 3493: "nut",
    3517: "ward", 3527: "veritas-tcp1", 3546: "eds-comm",
    3551: "apcupsd", 3580: "nati-vi-server", 3659: "apple-sasl",
    3689: "daap", 3690: "svn", 3703: "adobeserver-3",
    3737: "xpanel", 3766: "canon-ppp", 3784: "vcp",
    3800: "vhd", 3801: "vhd-ssl", 3809: "pscl-mgt",
    3869: "acp", 3871: "acp", 3878: "acp", 3880: "acp",
    3889: "acp", 3905: "mupdate", 3914: "listcrt-port",
    3918: "pktcablemmcos", 3920: "multicraft", 3945: "emcads",
    3971: "lanrevclient", 3986: "lanrevclient", 3995: "iss-mgmt-ssl",
    3998: "iss-mgmt-ssl", 4000: "icq", 4001: "newoak",
    4002: "newoak", 4003: "pxc-splr", 4004: "pxc-roid",
    4005: "pxc-pin", 4006: "pxc-spvr", 4045: "lockd",
    4111: "xgrid", 4125: "ddrepl", 4126: "ddrepl", 4129: "ddrepl",
    4224: "cocovision", 4242: "vrml-multi-use", 4279: "vrml-multi-use",
    4321: "rwhois", 4343: "unicall", 4443: "pharos",
    4444: "nv-video", 4445: "upnotifyp", 4446: "n1-fwp",
    4449: "privatewire", 4550: "gds-db", 4555: "rsip",
    4567: "sip-tls", 4662: "edonkey", 4848: "appserv-http",
    4899: "radmin", 4900: "hfcs", 4998: "ibm-db2",
    5000: "upnp", 5001: "plex", 5002: "plex", 5003: "filemaker",
    5004: "avt-profile-1", 5009: "airport-admin",
    5010: "telepathstart", 5011: "telepathattack",
    5020: "zebrasrv", 5021: "zebra", 5022: "zebra",
    5023: "h323gatestat", 5024: "h323gatestat", 5025: "h323gatestat",
    5029: "infi-async", 5030: "surfpass", 5037: "adb",
    5050: "mmcc", 5051: "ita-agent", 5052: "ita-manager",
    5060: "sip", 5061: "sip-tls", 5190: "aol-im",
    5200: "targus-getty", 5201: "targus-getty", 5214: "vsee",
    5221: "vsee", 5222: "xmpp-client", 5225: "hp-server",
    5226: "hp-server", 5269: "xmpp-server", 5280: "xmpp-bosh",
    5298: "xmpp-bosh", 5357: "wsdapi", 5405: "netsupport",
    5414: "netsupport", 5431: "park-agent", 5432: "postgresql",
    5440: "oracle-o2", 5500: "hotline", 5501: "hotline",
    5502: "hotline", 5503: "hotline", 5504: "hotline",
    5505: "hotline", 5506: "hotline", 5507: "hotline",
    5509: "hotline", 5510: "hotline", 5530: "stun",
    5544: "stun", 5550: "stun", 5554: "stun", 5555: "stun",
    5560: "stun", 5566: "stun", 5631: "pcanywheredata",
    5633: "pcanywherestat", 5666: "nrpe", 5672: "amqp",
    5718: "microsoft-ds", 5730: "microsoft-ds",
    5800: "vnc-http", 5801: "vnc-http", 5802: "vnc-http",
    5810: "vnc-http", 5811: "vnc-http", 5815: "vnc-http",
    5822: "vnc-http", 5825: "vnc-http", 5850: "vnc-http",
    5859: "vnc-http", 5862: "vnc-http", 5877: "submission",
    5900: "vnc", 5901: "vnc", 5902: "vnc", 5903: "vnc",
    5904: "vnc", 5906: "vnc", 5907: "vnc", 5910: "vnc",
    5911: "vnc", 5915: "vnc", 5922: "vnc", 5925: "vnc",
    5950: "vnc", 5952: "vnc", 5959: "vnc", 5960: "vnc",
    5961: "vnc", 5962: "vnc", 5963: "vnc",
    5987: "wbem-http", 5988: "wbem-https", 5989: "wbem-https",
    5999: "cvsup", 6000: "x11", 6001: "x11", 6002: "x11",
    6003: "x11", 6004: "x11", 6005: "x11", 6006: "x11",
    6007: "x11", 6009: "x11", 6346: "gnutella", 6389: "gnutella",
    6666: "irc", 6667: "irc", 6668: "irc", 6669: "irc",
    6697: "ircs", 6881: "bittorrent", 6901: "bittorrent",
    6969: "bittorrent", 7000: "bittorrent", 7001: "bittorrent",
    7002: "bittorrent", 7004: "bittorrent-tracker",
    7070: "realserver", 7100: "font-service",
    7443: "https-alt", 7777: "cbt", 7778: "cbt", 7800: "cbt",
    8000: "http-alt", 8001: "http-alt", 8002: "http-alt",
    8007: "http-alt", 8008: "http-alt", 8009: "ajp13",
    8010: "http-alt", 8011: "http-alt", 8021: "http-alt",
    8022: "http-alt", 8042: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8082: "http-alt",
    8083: "http-alt", 8084: "http-alt", 8085: "http-alt",
    8086: "http-alt", 8087: "http-alt", 8088: "http-alt",
    8089: "http-alt", 8090: "http-alt", 8100: "http-alt",
    8118: "privoxy", 8123: "polipo", 8124: "polipo",
    8180: "http-alt", 8181: "http-alt", 8200: "http-alt",
    8222: "http-alt", 8291: "http-alt", 8292: "http-alt",
    8300: "http-alt", 8333: "http-alt", 8400: "http-alt",
    8443: "https-alt", 8500: "http-alt", 8600: "http-alt",
    8649: "ganglia", 8800: "http-alt", 8888: "http-alt",
    8889: "http-alt", 9000: "cslistener", 9001: "tor-orport",
    9002: "tor-dirport", 9003: "tor-socks", 9009: "pichat",
    9040: "tor-trans", 9050: "tor-socks", 9071: "tor-socks",
    9080: "glrpc", 9090: "websm", 9091: "websm",
    9100: "pdl-datastream", 9101: "pdl-datastream",
    9102: "pdl-datastream", 9103: "pdl-datastream",
    9110: "pdl-datastream", 9111: "pdl-datastream",
    9200: "wap-wsp", 9418: "git", 9999: "abyss",
    10000: "ndmp", 10001: "ndmp", 10002: "ndmp",
    10003: "ndmp", 10004: "ndmp", 10005: "ndmp",
    10006: "ndmp", 10007: "ndmp", 10008: "ndmp",
    10009: "ndmp", 10010: "ndmp", 10012: "ndmp",
    10024: "ndmp", 10025: "ndmp", 10082: "amanda",
    10180: "amanda", 10215: "amanda", 10243: "amanda",
    10566: "amanda", 10616: "amanda", 10617: "amanda",
    10621: "amanda", 10626: "amanda", 10628: "amanda",
    10629: "amanda", 10778: "amanda", 11110: "amanda",
    11111: "amanda", 11967: "syslog-conn", 12000: "syslog-conn",
    12174: "syslog-conn", 12265: "syslog-conn", 12345: "netbus",
    13456: "netbus", 13722: "netbus", 13782: "netbus",
    13783: "netbus", 14000: "netbus", 14238: "netbus",
    14441: "netbus", 14442: "netbus", 15000: "netbus",
    15001: "netbus", 15002: "netbus", 15003: "netbus",
    15004: "netbus", 15660: "netbus", 15742: "netbus",
    16000: "netbus", 16001: "netbus", 16012: "netbus",
    16016: "netbus", 16018: "netbus", 16080: "netbus",
    16113: "netbus", 16992: "netbus", 16993: "netbus",
    17877: "netbus", 17988: "netbus", 18040: "netbus",
    18101: "netbus", 18988: "netbus", 19101: "netbus",
    19283: "netbus", 19315: "netbus", 19350: "netbus",
    19780: "netbus", 19801: "netbus", 19842: "netbus",
    20000: "dnp-sec", 20005: "dnp-sec", 20031: "dnp-sec",
    20221: "dnp-sec", 20222: "dnp-sec", 20828: "dnp-sec",
    21571: "dnp-sec", 22939: "dnp-sec", 23502: "dnp-sec",
    24444: "dnp-sec", 24800: "dnp-sec", 25734: "dnp-sec",
    25735: "dnp-sec", 26214: "dnp-sec", 27000: "flexlm",
    27352: "flexlm", 27353: "flexlm", 27355: "flexlm",
    27356: "flexlm", 27715: "flexlm", 28201: "flexlm",
    30000: "flexlm", 30718: "flexlm", 30951: "flexlm",
    31038: "flexlm", 31337: "back-orifice",
    32768: "filenet", 32769: "filenet", 32770: "filenet",
    32771: "filenet", 32772: "filenet", 32773: "filenet",
    32774: "filenet", 32775: "filenet", 32776: "filenet",
    32777: "filenet", 32778: "filenet", 32779: "filenet",
    32780: "filenet", 32781: "filenet", 32782: "filenet",
    32783: "filenet", 32784: "filenet", 32785: "filenet",
    33354: "filenet", 33899: "filenet", 34571: "filenet",
    34572: "filenet", 34573: "filenet", 35500: "filenet",
    38292: "filenet", 40193: "filenet", 40911: "filenet",
    41511: "filenet", 42510: "filenet", 44176: "filenet",
    44442: "filenet", 44443: "filenet", 44501: "filenet",
    45100: "filenet", 48080: "filenet",
    49152: "filenet", 49153: "filenet", 49154: "filenet",
    49155: "filenet", 49156: "filenet", 49157: "filenet",
    49158: "filenet", 49159: "filenet", 49160: "filenet",
    49161: "filenet", 49163: "filenet", 49165: "filenet",
    49167: "filenet", 49175: "filenet", 49176: "filenet",
    49400: "filenet", 49999: "filenet", 50000: "filenet",
    50001: "filenet", 50002: "filenet", 50003: "filenet",
    50006: "filenet", 50300: "filenet", 50389: "filenet",
    50500: "filenet", 50636: "filenet", 50800: "filenet",
    51103: "filenet", 51493: "filenet", 52673: "filenet",
    52822: "filenet", 52848: "filenet", 52869: "filenet",
    54045: "filenet", 54328: "filenet", 55055: "filenet",
    55056: "filenet", 55555: "filenet", 55600: "filenet",
    56737: "filenet", 56738: "filenet", 57294: "filenet",
    57797: "filenet", 58080: "filenet", 60020: "filenet",
    60443: "filenet", 61532: "filenet", 61900: "filenet",
    62078: "filenet", 63331: "filenet", 64623: "filenet",
    64680: "filenet", 65000: "filenet", 65129: "filenet",
    65389: "filenet",
}

def make_service_match(ports_dict):
    """Generate identify_service match arms"""
    lines = []
    for port in sorted(ports_dict.keys()):
        lines.append(f"        {port} => \"{ports_dict[port]}\",")
    lines.append("        _ => \"unknown\",")
    return "\n".join(lines)

# Build the full file content
full = content
full += f"""
pub const TOP_1000_PORTS: &[u16] = &[
{top1000_str}
];

pub fn identify_service(port: u16) -> &'static str {{
    match port {{
{make_service_match(service_ports)}
    }}
}}
"""

# Now add the remaining code (scan functions, banner grab, etc.)
full += r'''
fn make_probe(host: &str, port: u16) -> Option<&'static [u8]> {
    match port {
        21 => Some(b"HELP\r\n"),
        25 => Some(b"EHLO scanner\r\n"),
        80 | 8080 | 8888 => Some(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
        110 => Some(b"CAPA\r\n"),
        143 => Some(b"a001 CAPABILITY\r\n"),
        443 | 8443 => Some(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
        3306 => None,
        22 => None,
        _ => None,
    }
}
'''

# + the rest of functions
full += r'''
fn connect_host(host: &str, port: u16, timeout: Duration) -> Option<TcpStream> {
    let addr_str = format!("{}:{}", host, port);
    let addr = addr_str.parse::<SocketAddr>().ok()?;
    TcpStream::connect_timeout(&addr, timeout).ok()
}

pub fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let timeout = Duration::from_millis(timeout_ms);
    let mut stream = connect_host(host, port, timeout)?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    if let Some(probe) = make_probe(host, port) {
        let _ = stream.write_all(probe);
    }

    let mut buf = [0u8; 2048];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => {
            let clean: Vec<u8> = buf[..n].iter().copied()
                .filter(|&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r')
                .collect();
            let banner = String::from_utf8_lossy(&clean).trim().to_string();
            if banner.is_empty() { None } else { Some(banner) }
        }
        _ => None,
    }
}

pub fn detect_service_version(host: &str, port: u16, banner: &str) -> ServiceInfo {
    let service = identify_service(port).to_string();
    let lower = banner.to_lowercase();

    fn extract_version(s: &str, prefixes: &[&str]) -> Option<String> {
        for p in prefixes {
            if let Some(idx) = s.find(p) {
                let rest = &s[idx + p.len()..];
                let end = rest.find(|c: char| !c.is_alphanumeric() && c != '.' && c != '_' && c != '-' && c != 'p' && c != '~').unwrap_or(rest.len());
                let ver = rest[..end].trim().to_string();
                if !ver.is_empty() { return Some(ver); }
            }
        }
        None
    }

    let (product, version, os_hint) = match port {
        22 => {
            if lower.contains("openssh") {
                let ver = extract_version(banner, &["OpenSSH_", "openssh_", "openssh "]);
                let os = if lower.contains("ubuntu") { Some("Ubuntu Linux".into()) }
                else if lower.contains("debian") { Some("Debian Linux".into()) }
                else if lower.contains("freebsd") { Some("FreeBSD".into()) }
                else if lower.contains("windows") { Some("Windows".into()) }
                else { Some("Linux/Unix".into()) };
                (Some("OpenSSH".into()), ver, os)
            } else if lower.contains("dropbear") {
                let ver = extract_version(banner, &["dropbear_"]);
                (Some("Dropbear SSH".into()), ver, Some("Linux/Embedded".into()))
            } else {
                (None, None, None)
            }
        }
        80 | 8080 | 8888 => {
            if let Some(idx) = lower.find("server:") {
                let rest = &lower[idx + 7..];
                let end = rest.find('\r').unwrap_or_else(|| rest.find('\n').unwrap_or(rest.len()));
                let server_line = rest[..end].trim().to_string();
                let parts: Vec<&str> = server_line.split('/').collect();
                let prod = parts[0].to_string();
                let ver = parts.get(1).map(|s| {
                    let end = s.find(|c: char| !c.is_alphanumeric() && c != '.' && c != '_' && c != '~').unwrap_or(s.len());
                    s[..end].to_string()
                });
                let os = if server_line.contains("Ubuntu") { Some("Ubuntu Linux".into()) }
                else if server_line.contains("Debian") { Some("Debian Linux".into()) }
                else if server_line.contains("CentOS") || server_line.contains("Red Hat") { Some("Red Hat Linux".into()) }
                else if server_line.contains("Win") || server_line.contains("IIS") { Some("Windows".into()) }
                else if server_line.contains("nginx") { Some("Linux/Unix".into()) }
                else if server_line.contains("Apache") { Some("Linux/Unix".into()) }
                else { None };
                (Some(prod), ver, os)
            } else if lower.contains("nginx") {
                let ver = extract_version(banner, &["nginx/"]);
                (Some("nginx".into()), ver, Some("Linux/Unix".into()))
            } else if lower.contains("apache") {
                let ver = extract_version(banner, &["Apache/"]);
                let os = if lower.contains("ubuntu") { Some("Ubuntu Linux".into()) }
                else if lower.contains("debian") { Some("Debian Linux".into()) }
                else { Some("Linux/Unix".into()) };
                (Some("Apache httpd".into()), ver, os)
            } else if lower.contains("iis") {
                let ver = extract_version(banner, &["iis ", "IIS/"]);
                (Some("IIS".into()), ver, Some("Windows".into()))
            } else {
                (None, None, None)
            }
        }
        21 => {
            let prod;
            if lower.contains("proftpd") { prod = Some("ProFTPD".into()); }
            else if lower.contains("vsftpd") { prod = Some("vsftpd".into()); }
            else if lower.contains("pure-ftpd") { prod = Some("Pure-FTPd".into()); }
            else if lower.contains("filezilla") { prod = Some("FileZilla".into()); }
            else if lower.contains("microsoft ftp") || lower.contains("microsoft ftp service") { prod = Some("MS FTP".into()); }
            else { prod = None; }
            let ver = match &prod {
                Some(_) => extract_version(banner, &["version ", "ver "]),
                None => None,
            };
            let os = if lower.contains("windows") || lower.contains("microsoft") { Some("Windows".into()) }
            else { None };
            (prod, ver, os)
        }
        25 => {
            if lower.contains("postfix") { (Some("Postfix".into()), None, Some("Linux/Unix".into())) }
            else if lower.contains("exim") {
                let ver = extract_version(banner, &["exim "]);
                (Some("Exim".into()), ver, Some("Linux/Unix".into()))
            }
            else if lower.contains("sendmail") {
                let ver = extract_version(banner, &["sendmail "]);
                (Some("Sendmail".into()), ver, Some("Linux/Unix".into()))
            }
            else if lower.contains("microsoft") || lower.contains("exchange") { (Some("Exchange".into()), None, Some("Windows".into())) }
            else if lower.contains("qmail") { (Some("qmail".into()), None, Some("Linux/Unix".into())) }
            else { (None, None, None) }
        }
        110 => {
            if lower.contains("dovecot") { (Some("Dovecot".into()), None, Some("Linux/Unix".into())) }
            else if lower.contains("courier") { (Some("Courier".into()), None, Some("Linux/Unix".into())) }
            else if lower.contains("microsoft") || lower.contains("exchange") { (Some("MS Exchange".into()), None, Some("Windows".into())) }
            else { (None, None, None) }
        }
        143 => {
            if lower.contains("dovecot") { (Some("Dovecot".into()), None, Some("Linux/Unix".into())) }
            else if lower.contains("courier") { (Some("Courier".into()), None, Some("Linux/Unix".into())) }
            else if lower.contains("exchange") || lower.contains("microsoft") { (Some("MS Exchange".into()), None, Some("Windows".into())) }
            else { (None, None, None) }
        }
        3306 => {
            if lower.contains("mysql") || lower.contains("mariadb") {
                let ver = if let Some(idx) = banner.find(|c: char| c.is_ascii_digit()) {
                    let rest = &banner[idx..];
                    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(rest.len());
                    Some(rest[..end].to_string())
                } else { None };
                if lower.contains("mariadb") { (Some("MariaDB".into()), ver, Some("Linux/Unix".into())) }
                else { (Some("MySQL".into()), ver, Some("Linux/Unix".into())) }
            } else { (None, None, None) }
        }
        443 | 8443 => {
            if lower.contains("apache") { (Some("Apache httpd".into()), None, Some("Linux/Unix".into())) }
            else if lower.contains("nginx") { (Some("nginx".into()), None, Some("Linux/Unix".into())) }
            else if lower.contains("iis") { (Some("IIS".into()), None, Some("Windows".into())) }
            else { (None, None, None) }
        }
        5900 | 5901 => {
            if lower.contains("tightvnc") { (Some("TightVNC".into()), None, Some("Linux/Unix".into())) }
            else if lower.contains("realvnc") || lower.contains("vnc") { (Some("RealVNC".into()), None, None) }
            else { (None, None, None) }
        }
        3389 => {
            (Some("MS RDP".into()), None, Some("Windows".into()))
        }
        _ => (None, None, None),
    };

    ServiceInfo {
        port,
        state: PortState::Open,
        service,
        product,
        version,
        banner: Some(banner.to_string()),
        os_hint,
    }
}

pub fn scan_port_with_banner(host: &str, port: u16) -> Option<ServiceInfo> {
    let timeout = Duration::from_millis(1500);
    let stream = connect_host(host, port, timeout)?;
    drop(stream);

    let banner = grab_banner(host, port, 1500);
    let service = identify_service(port).to_string();

    if let Some(ref b) = banner {
        let detected = detect_service_version(host, port, b);
        Some(ServiceInfo {
            port,
            state: PortState::Open,
            service,
            product: detected.product,
            version: detected.version,
            banner: Some(b.clone()),
            os_hint: detected.os_hint,
        })
    } else {
        Some(ServiceInfo {
            port,
            state: PortState::Open,
            service,
            product: None,
            version: None,
            banner: None,
            os_hint: None,
        })
    }
}

fn resolve_host(host: &str) -> Option<String> {
    let addr = host.parse::<SocketAddr>().ok()?;
    Some(addr.ip().to_string())
}

fn scan_chunk(host: &str, ports: &[u16], timeout_ms: u64) -> Vec<u16> {
    let open_ref = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for &port in ports {
        let host_str = host.to_string();
        let open = Arc::clone(&open_ref);
        let timeout = Duration::from_millis(timeout_ms);
        let handle = thread::spawn(move || {
            let addr_str = format!("{}:{}", host_str, port);
            if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                    let mut locked = open.lock().unwrap();
                    locked.push(port);
                }
            }
        });
        handles.push(handle);
    }

    for h in handles { let _ = h.join(); }
    let mut ports = open_ref.lock().unwrap().clone();
    ports.sort();
    ports
}

pub fn port_scan(host: &str, ports: &[u16]) -> Vec<u16> {
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for chunk in ports.chunks(100) {
        let chunk_vec: Vec<u16> = chunk.to_vec();
        let host_str = host.to_string();
        let open_ref = Arc::clone(&open_ports);

        let handle = thread::spawn(move || {
            let local_open = scan_chunk(&host_str, &chunk_vec, 200);
            if !local_open.is_empty() {
                let mut locked = open_ref.lock().unwrap();
                locked.extend(local_open);
            }
        });
        handles.push(handle);
    }

    for h in handles { let _ = h.join(); }

    let mut final_ports = open_ports.lock().unwrap().clone();
    final_ports.sort();
    final_ports.dedup();
    for &p in &final_ports {
        println!("[RUST-SCAN] PORT OPEN: {}:{}", host, p);
    }
    final_ports
}

pub fn port_scan_full(host: &str, port_range: &str) -> PortScanResult {
    let start = Instant::now();
    let ip = resolve_host(host).unwrap_or_else(|| host.to_string());
    let ports = parse_port_range(port_range);

    let open_ports = port_scan(host, &ports);
    let scan_time = start.elapsed();

    let services: Vec<ServiceInfo> = open_ports.iter().map(|&port| {
        let banner = grab_banner(host, port, 1500);
        let service = identify_service(port).to_string();
        let detected = banner.as_ref()
            .map(|b| detect_service_version(host, port, b));
        ServiceInfo {
            port,
            state: PortState::Open,
            service,
            product: detected.as_ref().and_then(|d| d.product.clone()),
            version: detected.as_ref().and_then(|d| d.version.clone()),
            banner,
            os_hint: detected.as_ref().and_then(|d| d.os_hint.clone()),
        }
    }).collect();

    PortScanResult {
        host: host.to_string(),
        ip,
        scan_time_ms: scan_time.as_millis() as u64,
        total_open: services.len(),
        os_guess: os_detect(host),
        ports: services,
    }
}

pub fn port_scan_stealth(host: &str, ports: &[u16], timeout_ms: u64) -> Vec<u16> {
    println!("[RUST-SCAN] SYN scan not available (requires root + pcap). Falling back to TCP Connect.");
    scan_chunk(host, ports, timeout_ms)
}

pub fn os_detect(host: &str) -> Option<String> {
    if let Some(banner) = grab_banner(host, 22, 1000) {
        let lower = banner.to_lowercase();
        if lower.contains("windows") { return Some("Windows Server (SSH)".into()); }
        if lower.contains("ubuntu") { return Some("Ubuntu Linux".into()); }
        if lower.contains("debian") { return Some("Debian Linux".into()); }
        if lower.contains("freebsd") { return Some("FreeBSD".into()); }
        if lower.contains("openssh") { return Some("Linux/Unix (OpenSSH)".into()); }
        if lower.contains("dropbear") { return Some("Linux/Embedded (Dropbear)".into()); }
    }

    if let Some(banner) = grab_banner(host, 80, 1000) {
        let lower = banner.to_lowercase();
        if lower.contains("windows") || lower.contains("iis") { return Some("Windows (IIS)".into()); }
        if lower.contains("nginx") { return Some("Linux (Nginx)".into()); }
        if lower.contains("apache") {
            if lower.contains("ubuntu") { return Some("Ubuntu Linux (Apache)".into()); }
            if lower.contains("debian") { return Some("Debian Linux (Apache)".into()); }
            if lower.contains("centos") || lower.contains("red hat") { return Some("Red Hat Linux (Apache)".into()); }
            return Some("Linux/BSD (Apache)".into());
        }
    }

    if let Some(banner) = grab_banner(host, 445, 1000) {
        let lower = banner.to_lowercase();
        if lower.contains("windows") || lower.contains("samba") { }
        return Some("Windows (SMB)".into());
    }

    if let Some(banner) = grab_banner(host, 3389, 1000) {
        let lower = banner.to_lowercase();
        if lower.contains("rdp") || lower.contains("terminal") || lower.contains("windows") {
            return Some("Windows (RDP)".into());
        }
    }

    if let Some(banner) = grab_banner(host, 21, 1000) {
        let lower = banner.to_lowercase();
        if lower.contains("windows") || lower.contains("microsoft") {
            return Some("Windows (FTP)".into());
        }
    }

    Some("Unknown OS".into())
}

pub fn arp_scan_subnet(subnet: &str) -> Vec<HostRecord> {
    let base = subnet.trim_end_matches("/24").trim_end_matches(".0");
    let hosts: Arc<Mutex<Vec<HostRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    for last_octet in 1u8..=254u8 {
        let hosts_ref = Arc::clone(&hosts);
        let ip = format!("{}.{}", base, last_octet);
        let handle = thread::spawn(move || {
            let start = Instant::now();
            let alive = ping_host(&ip, 300);
            let latency = start.elapsed().as_secs_f32() * 1000.0;
            if alive {
                let record = HostRecord {
                    ip: ip.clone(),
                    mac: resolve_arp_mac(&ip),
                    hostname: None,
                    open_ports: vec![],
                    os_guess: None,
                    ttl: None,
                    latency_ms: latency,
                };
                let mut h = hosts_ref.lock().unwrap();
                h.push(record);
            }
        });
        handles.push(handle);
    }

    for h in handles { let _ = h.join(); }

    let final_results = hosts.lock().unwrap().clone();
    for rec in &final_results {
        println!("[RUST-RECON] HOST: ip={} mac={} hostname={} latency={:.1}ms",
            rec.ip,
            rec.mac.as_deref().unwrap_or("N/A"),
            rec.hostname.as_deref().unwrap_or("N/A"),
            rec.latency_ms
        );
    }
    final_results
}

fn resolve_arp_mac(ip: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("arp").arg("-a").output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains(ip) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Some(parts[1].to_uppercase().replace("-", ":"));
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.get(0) == Some(&ip) {
                    return parts.get(3).map(|m| m.to_uppercase());
                }
            }
        }
    }
    None
}

fn ping_host(ip: &str, timeout_ms: u64) -> bool {
    #[cfg(target_os = "windows")]
    let output = std::process::Command::new("ping")
        .args(["-n", "1", "-w", &timeout_ms.to_string(), ip])
        .output();
    #[cfg(not(target_os = "windows"))]
    let output = std::process::Command::new("ping")
        .args(["-c", "1", "-W", &(timeout_ms / 1000).max(1).to_string(), ip])
        .output();
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

pub fn arp_spoof(target: &str, gateway: &str) -> Result<(), String> {
    if cfg!(target_os = "windows") {
        let add_cmd = format!("netsh interface ip add neighbors \"Local Area Connection\" {} 12-34-56-78-9A-BC", target);
        let _ = std::process::Command::new("cmd").args(["/C", &add_cmd]).output();
        println!("[MITM-ARP] Poisoning {} -> gateway {}", target, gateway);
        Ok(())
    } else if cfg!(target_os = "linux") {
        for _ in 0..5 {
            let cmd = format!("arping -U -I $(ip route get {} | grep dev | awk '{print $5}') {} 2>/dev/null", gateway, target);
            let _ = std::process::Command::new("sh").args(["-c", &cmd]).output();
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        Ok(())
    } else {
        Err("ARP spoofing requires root on this platform".into())
    }
}

pub fn dns_spoof(_interface: &str, _fake_ip: &str) -> Result<(), String> {
    let msg = format!("[MITM-DNS] Use bettercap/dnschef: bettercap -eval 'set arp.spoof.targets {}; arp.spoof on; dns.spoof on'", _interface);
    println!("{}", msg);
    Ok(())
}

pub fn ssl_strip(listen_port: u16) -> Result<(), String> {
    println!("[MITM-SSL] Use mitmproxy for SSL stripping: mitmproxy --listen-port {}", listen_port);
    println!("[MITM-SSL] iptables: iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {}", listen_port);
    Ok(())
}

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    3306, 3389, 5900, 8080, 8443, 1194, 1723, 4444, 5555
];
'''

with open(path, 'w', encoding='utf-8') as f:
    f.write(full)

print(f"Written {len(full)} bytes to {path}")
