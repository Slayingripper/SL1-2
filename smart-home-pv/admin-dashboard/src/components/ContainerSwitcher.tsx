import React, { useEffect, useState } from 'react';
import './ContainerSwitcher.css';

interface ContainerInfo {
  name: string;
  internal_ip: string;
  ssh_user?: string;
  host_ssh_port?: number | null;
  admin_host_port?: number | null;
}

const ContainerSwitcher: React.FC = () => {
  const [containers, setContainers] = useState<Record<string, ContainerInfo>>({});
  const [selected, setSelected] = useState<string | null>(null);
  const host = window.location.hostname;
  const [open, setOpen] = useState<boolean>(false);

  useEffect(() => {
    const fetchContainers = async () => {
      try {
        const resp = await fetch('/api/containers');
        if (!resp.ok) return;
        const data = await resp.json();
        setContainers(data);
        const keys = Object.keys(data);
        if (keys.length) setSelected(keys[0]);
      } catch (e) {
        console.debug('Failed to load containers', e);
      }
    };
    fetchContainers();
  }, []);

  const copySSH = (info: ContainerInfo | undefined) => {
    if (!info || !info.host_ssh_port) return;
    const command = `ssh -p ${info.host_ssh_port} ${info.ssh_user || 'root'}@${host}`;
    navigator.clipboard.writeText(command).then(() => { alert('Copied: ' + command); });
  };

  const copyDockerExec = (info: ContainerInfo | undefined) => {
    if (!info) return;
    const command = `docker exec -it ${info.name} bash`;
    navigator.clipboard.writeText(command).then(() => { alert('Copied: ' + command); });
  };

  return (
    <div className="container-switcher">
      <button className="gear-btn" title="Switch container" onClick={() => setOpen(!open)}>⚙️</button>
      {open && (
        <>
          <div className="switcher-label">Connect</div>
          <select value={selected || ''} onChange={(e) => setSelected(e.target.value)}>
        {Object.keys(containers).map(k => (
          <option key={k} value={k}>{k}</option>
        ))}
      </select>

        </>
      )}

      {open && selected && containers[selected] && (
        <div className="conn-info">
          <div className="conn-row"><strong>Container:</strong> {containers[selected].name}</div>
          <div className="conn-row"><strong>Internal IP:</strong> {containers[selected].internal_ip}</div>
          <div className="conn-row"><strong>Host SSH Port:</strong> {containers[selected].host_ssh_port || 'unmapped'}</div>
          <div className="conn-actions">
            <button className="action-btn" onClick={() => copyDockerExec(containers[selected])}>Copy docker exec</button>
            {containers[selected].host_ssh_port ? (
              <button className="action-btn" onClick={() => copySSH(containers[selected])}>Copy SSH</button>
            ): (
              <button className="action-btn disabled" disabled>Host SSH unmapped</button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ContainerSwitcher;
