#fetch interfaces from the system
from psutil import net_if_addrs
addrs = net_if_addrs()
