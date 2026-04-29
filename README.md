Noyra - orchestrator/scheduler for Podman
=========================================

L'idée de Noyra est née d'un constat simple : il n'existe pas de "pico-Kubernetes", un orchestrateur léger adapté aux petites infrastructures.  
Docker Swarm et Nomad, les alternatives les plus proches, souffrent de limitations rédhibitoires.

Docker Swarm
------------
- **Exécution root obligatoire**  
    le daemon Docker tourne en root par défaut, ce qui élargit considérablement la surface d'attaque et complique le déploiement dans des environnements contraints ou multi-tenant.
- **Daemon monolithique fragile**  
    toute l'orchestration repose sur un unique processus ; s'il crashe, l'ensemble du nœud devient aveugle au cluster, sans mécanisme de récupération gracieux.
- **Dépendance forcée à iptables**  
    la gestion réseau est intimement couplée à iptables, rendant l'intégration avec des firewalls modernes (nftables, eBPF) complexe et la posture de sécurité difficile à auditer.

HashiCorp Nomad
---------------
- **Écosystème payant et verrouillé**  
    les fonctionnalités essentielles pour la production (namespaces, SSO, audit logs) sont réservées à la licence Enterprise, rendant la version gratuite insuffisante au-delà d'un usage basique.
- **Complexité opérationnelle sous-estimée**  
    Nomad nécessite de déployer et opérer séparément Consul (service mesh) et Vault (secrets), transformant un orchestrateur "simple" en une stack de trois projets distincts à maintenir.
- **Modèle de sécurité permissif par défaut**  
    l'ACL et le chiffrement mTLS entre agents ne sont pas activés out-of-the-box, laissant des clusters entiers exposés si la configuration n'est pas durcie manuellement.

![Schema](docs/schema.svg)


État actuel du projet
---------------------
Rien n'est fonctionnel, c'est le tout début du projet.  
Ce projet est public au cas où vous voudriez voir mes tribulations dans ce projet.

Au début je voulais gérer le fait que Noyra puisse gérer plusieurs serveurs physiques.  
Cependant afin de rester KISS et travailler correctement, je vais déjà me focaliser sur le fait que Noyra fonctionne correctement sur un serveur physique.
