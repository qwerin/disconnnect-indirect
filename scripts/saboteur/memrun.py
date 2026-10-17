# memrun.py <rss_file> <timeout> cmd... : spustí příkaz s limitem času, zapíše max RSS (KB), vrátí exit kód
import resource, subprocess, sys
rss_file, to, cmd = sys.argv[1], float(sys.argv[2]), sys.argv[3:]
try:
    p = subprocess.run(cmd, timeout=to)
    code = p.returncode
except subprocess.TimeoutExpired:
    code = "TIMEOUT"
open(rss_file, "w").write(str(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss))
print(code)
