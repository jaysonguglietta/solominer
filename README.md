# SoloMiner

Fedora-first instructions for running a low-intensity solo Bitcoin CPU miner as a background service.

This project is aimed at people who want to run a "lottery miner" on machines that are already on, understand the odds are extremely low, and still want a clean setup they can install, monitor, and maintain.

## Important Notes

- This is not a profitable Bitcoin mining setup on normal desktop or server CPUs.
- This is best treated as a hobby or educational setup.
- The instructions below use `cpuminer-opt` for CPU mining and `systemd` for background operation.
- Use conservative thread counts if you care about noise, thermals, or server responsiveness.

## What This Setup Does

- Builds `cpuminer-opt` on Fedora
- Installs it into a permanent path under `/opt/cpuminer-opt`
- Runs it as a background `systemd` service
- Restarts automatically if it crashes
- Starts automatically after reboot
- Keeps settings in a simple environment file

## Pool Options

These instructions are written around the public NerdMiner-compatible endpoint:

- Primary: `stratum+tcp://pool.nerdminer.de:3333`
- Fallback: `stratum+tcp://pool.nerdminer.io:3333`

If you prefer, you can also swap in another solo pool endpoint such as Solo CKPool.

## Prerequisites

- Fedora Linux
- A Bitcoin receive address
- Internet access from the Fedora host
- Root or sudo access

## Clone This Repository

```bash
git clone git@github.com:jaysonguglietta/solominer.git
cd solominer
```

## Recommended Defaults

For always-on systems, start conservatively:

- Use `THREADS=2` on lower-core systems
- Use about half your logical CPUs if you want to tune higher later
- Keep sustained temperatures under about `80C` / `176F`

## Install Dependencies

```bash
sudo dnf -y group install "Development Tools"
sudo dnf -y install git automake autoconf libcurl-devel jansson-devel gmp-devel zlib-devel lm_sensors thermald
```

## Enable Temperature Monitoring

```bash
sudo sensors-detect --auto
sudo systemctl enable --now thermald
watch -n 2 'sensors -f'
```

## Create a Dedicated Service User

Running the miner as a dedicated system user is safer than running it as `root`.

```bash
sudo useradd --system --create-home --home-dir /opt/cpuminer-opt --shell /sbin/nologin solominer
```

## Download and Build `cpuminer-opt`

Build in a temporary directory, then install into a permanent one.

```bash
cd /tmp
git clone https://github.com/JayDDee/cpuminer-opt.git
cd cpuminer-opt
./build.sh
```

If `./build.sh` fails, use the manual build path:

```bash
./autogen.sh
CFLAGS="-O3 -march=native -Wall" ./configure --with-curl
make -j"$(nproc)"
```

## Install the Miner into a Permanent Location

```bash
sudo install -d -o solominer -g solominer /opt/cpuminer-opt
sudo cp -a /tmp/cpuminer-opt/. /opt/cpuminer-opt/
sudo chown -R solominer:solominer /opt/cpuminer-opt
ls -l /opt/cpuminer-opt/cpuminer
```

## Quick Manual Test

Before creating the service, confirm the miner can connect.

Replace `YOUR_BTC_ADDRESS` and choose a worker name such as `fedora1`.

```bash
sudo -u solominer /opt/cpuminer-opt/cpuminer -a sha256d \
  -o stratum+tcp://pool.nerdminer.de:3333 \
  -u YOUR_BTC_ADDRESS.fedora1 \
  -p x \
  -t 2
```

If the `.de` endpoint does not connect, retry with:

```bash
stratum+tcp://pool.nerdminer.io:3333
```

Stop the manual test with `Ctrl+C` after confirming it connects and starts hashing.

## Create the Miner Environment File

Copy the example file in this repository:

```bash
sudo cp systemd/btc-solo-cpu.env.example /etc/sysconfig/btc-solo-cpu
sudo chmod 640 /etc/sysconfig/btc-solo-cpu
```

Edit the file:

```bash
sudoedit /etc/sysconfig/btc-solo-cpu
```

Set these values:

- `POOL`: your pool URL
- `WALLET`: your Bitcoin address
- `WORKER`: a unique worker name per machine, such as `fedora1` or `fedora2`
- `THREADS`: start conservatively, such as `2`

Example:

```bash
POOL=stratum+tcp://pool.nerdminer.de:3333
WALLET=bc1qexampleexampleexampleexampleexample
WORKER=fedora1
THREADS=2
```

## Install the `systemd` Service

Copy the service file from this repository:

```bash
sudo cp systemd/btc-solo-cpu.service /etc/systemd/system/btc-solo-cpu.service
sudo systemctl daemon-reload
```

Enable and start it:

```bash
sudo systemctl enable --now btc-solo-cpu.service
```

## See Status on the Fedora Machine

Show service state:

```bash
sudo systemctl status btc-solo-cpu.service
```

Watch live miner logs:

```bash
sudo journalctl -u btc-solo-cpu.service -f
```

Show recent logs:

```bash
sudo journalctl -u btc-solo-cpu.service -n 100 --no-pager
```

Confirm the miner process exists:

```bash
ps aux | grep cpuminer
```

Check temperatures in Fahrenheit:

```bash
watch -n 2 'sensors -f'
```

## Thread Tuning

Start low and increase only if temperatures stay comfortable.

Useful helpers:

```bash
nproc
echo $(( $(nproc) / 2 ))
```

Practical guidance:

- `THREADS=2`: safer starting point for always-on systems
- `THREADS=4`: reasonable if temperatures stay under control
- Avoid using every logical CPU unless you do not care about heat or interactivity

If the system feels slow or hot:

- lower `THREADS`
- restart the service
- let it run for 15 to 30 minutes and watch temperatures

## Service Management

Start:

```bash
sudo systemctl start btc-solo-cpu.service
```

Stop:

```bash
sudo systemctl stop btc-solo-cpu.service
```

Restart:

```bash
sudo systemctl restart btc-solo-cpu.service
```

Disable auto-start:

```bash
sudo systemctl disable btc-solo-cpu.service
```

## Maintenance

### Update Fedora Packages

These update with normal Fedora maintenance:

```bash
sudo dnf upgrade --refresh
```

This includes packages such as:

- `git`
- `automake`
- `autoconf`
- `libcurl-devel`
- `jansson-devel`
- `gmp-devel`
- `zlib-devel`
- `lm_sensors`
- `thermald`

### Update the Miner

The miner binary installed under `/opt/cpuminer-opt` does not update itself. Rebuild it manually:

```bash
cd /tmp
rm -rf /tmp/cpuminer-opt
git clone https://github.com/JayDDee/cpuminer-opt.git
cd /tmp/cpuminer-opt
./build.sh
sudo cp -f /tmp/cpuminer-opt/cpuminer /opt/cpuminer-opt/cpuminer
sudo chown solominer:solominer /opt/cpuminer-opt/cpuminer
sudo systemctl restart btc-solo-cpu.service
```

### Change Wallet, Worker, Pool, or Threads

Edit the environment file:

```bash
sudoedit /etc/sysconfig/btc-solo-cpu
sudo systemctl restart btc-solo-cpu.service
```

## Cooling Tips

If you want the machine to stay cool:

- use fewer threads
- keep `Nice=15` in the service
- make sure `thermald` is running
- watch `sensors`

If temperatures are still too high, you can temporarily disable Intel Turbo Boost:

```bash
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
```

Re-enable it later with:

```bash
echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
```

## Troubleshooting

### `status=217/USER`

This usually means the `User=` in the service file does not exist.

Fix it by creating the `solominer` system user and reloading `systemd`.

### Miner Path Not Found

If the service points to `/tmp/cpuminer-opt`, move the miner to `/opt/cpuminer-opt`. `/tmp` is not a safe permanent location for services.

### Pool Connection Fails

Try the fallback endpoint:

```bash
POOL=stratum+tcp://pool.nerdminer.io:3333
```

Then restart:

```bash
sudo systemctl restart btc-solo-cpu.service
```

### Machine Is Too Hot

Lower the thread count in `/etc/sysconfig/btc-solo-cpu`:

```bash
THREADS=2
```

Then restart the service.

## Running Two Fedora Servers

Use the same wallet on both machines, but give each one a different worker name.

Example:

- Server 1: `WORKER=fedora1`
- Server 2: `WORKER=fedora2`

That lets you identify each machine in pool dashboards while sending any winning payout to the same Bitcoin address.
