# M13 

**Classification:** Aerospace / High-Frequency Transport (HFT) Grade  
**Target Hardware:** AMD/Xilinx Kria K26 SOM + Zynq UltraScale+ FPGA + Custom PCB  
**Testbench Architecture:** x86_64 (AVX2/AES-NI) for CI/CD and fixed ground-station Hubs  
**Operating System:** AMD Embedded Development Framework (EDF) Yocto Project (Scarthgap 5.0 LTS) / **Linux Kernel 6.12 LTS+**  
> **ARCHITECTURAL MANDATE:** Legacy PetaLinux distributions are explicitly End-of-Life (EOL) and physically incompatible with the M13 datapath. Kernel 6.12+ is a hard architectural requirement to enable `io_uring` Provided Buffer Rings (PBR), `IORING_RECV_MULTISHOT`, and advanced `XDP_REDIRECT` primitives.

## End-State System Topology

> [!NOTE]
> This section describes M13's **end-state architecture** — the fully realized system as designed. Individual subsystems are at varying stages of implementation; see `TODO.md` for current sprint status and the roadmap.

M13 is a Beyond Visual Line of Sight (BVLOS) drone swarm operation design with a hub-nodes topology.

* **Hub (LALE Drone):** The Hub functions as a "flying telco" (Airborne Network Gateway), aggregating heterogeneous, asymmetric satellite uplinks (e.g., Starlink, Amazon Kuiper, Eutelsat) into a bonded, multipath-scheduled backhaul and broadcasting a WiFi 7 Access Point (AP) for the daughter drone swarm.

* **Nodes (WAN-deprived Daughter Drone Swarm):** Tactical drones without inherent Wide Area Network (WAN) hardware interfaces. Nodes associate with the Hub's WiFi 7 AP, achieving end-to-end connectivity to the User exclusively via the M13 L3 encrypted tunnel over the local WLAN.

* **User (Command Center):** The user controls both the Hub and the daughter drone swarm via remote infrastructure connected to an Internet Service Provider (ISP). M13 operates strictly at the transport layer, acting as a transparent, opaque IP tunnel entirely agnostic to the L7 application protocols (MAVLink/Video) executing above it.

The value of M13 is not any single component in isolation — it is the integrated system competing directly against Silvus StreamCaster (~$15K–$30K/node), Persistent Systems MPU5 (~$30K–$35K/node), L3Harris AN/PRC-163 MANET (~$39K/radio), and MIDS-JTRS Link 16 terminals (~$186K–$263K/terminal) for BVLOS drone **swarm** command and control. These incumbents are proven, combat-deployed systems — but they are priced for defense prime procurement, not for scalable swarm deployment where every daughter drone in the formation requires a node. Critically, M13 is both the drone and the network — the incumbents above are network radios only, bolted onto someone else's airframe. M13 targets a per-node cost at a fraction of these price points (target: TBD), making swarm-scale BVLOS architectures economically viable for the first time outside of nation-state budgets.

Furthermore, this price-point disproportion means M13 is not domain-locked. It is a multi-usage hub-swarm design: 
- **search and rescue**, where every minute matters — a swarm of drones mapping the area comprehensively in a fraction of the time a single aircraft could; 
- **disaster connectivity**, such as floods or earthquakes that destroy ground telco infrastructure — M13 deploys as an airborne mesh providing emergency internet to affected users, enabling them to report their location and coordinate rescue; 
- **humanitarian logistics**, where daughter drones deliver food, water, heating, or basic medical supplies to stranded populations until ground-based rescue arrives; 
- **infrastructure inspection**, where swarms survey pipelines, power grids, or coastline at scale. 

Across all of these, the daughter drones are attritable and the per-node price point is low enough to enable multi-strategy deployment within a single mission. A LALE mothership Hub holds station at altitude for an extended period to provide persistent SATCOM backhaul; *x* daughter Nodes hold stagnant positions to monitor specific areas of interest; *y* daughter Nodes patrol in continuous movement patterns — together, this covers maximum area with minimal line-of-sight gaps. When a worker drone's battery runs low, a fresh drone deploys from the origin and seamlessly joins the mesh — the spent drone returns to base. This rotation model turns endurance from a single-drone engineering problem into a logistics problem solved by quantity: continuous coverage with no downtime, at a cost where losing a Node to weather, attrition, or terrain is an acceptable operational expense rather than a mission-ending loss.

The incumbents are priced out of all of these. M13 makes it possible.