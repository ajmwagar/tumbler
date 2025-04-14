<script lang="ts">
  import { onMount } from 'svelte';
  import { Copy } from 'lucide-svelte';

  type CertEntry = {
    name: string;
    ca: string;
    cert_path: string;
    key_path: string;
  };

  let certs: CertEntry[] = [];
  let name = '';
  let domain = '';
  let folder = '';
  let client = false;
  let showModal = false;

  const loadCerts = async () => {
    const res = await fetch('https://localhost:6969/list');
    certs = await res.json();
  };

  const generateCert = async () => {
    await fetch(`https://localhost:6969/generate?name=${name}&domain=${domain}&folder=${folder}&client=${client}`);
    showModal = false;
    name = domain = folder = '';
    await loadCerts();
  };

  const copyCurl = (name: string) => {
    const curl = `curl -k https://localhost:6969/${name}/cert > ${name}.cert; curl -k https://localhost:6969/${name}/key > ${name}.key`;
    navigator.clipboard.writeText(curl);
  };

  onMount(loadCerts);
</script>

<div class="p-6 space-y-6 max-w-4xl mx-auto">
  <div class="flex justify-between items-center">
    <h1 class="text-2xl font-bold">Certificates</h1>
    <button
      class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
      on:click={() => (showModal = true)}
    >
      Generate New Cert
    </button>
  </div>

  {#each certs as cert}
    <div class="border rounded p-4 shadow flex flex-col gap-2">
      <div class="text-lg font-semibold">{cert.name}</div>
      <div class="text-sm text-gray-500">CA: {cert.ca}</div>
      <div class="flex gap-2 mt-2 flex-wrap">
        <button class="bg-green-600 text-white px-3 py-1 rounded hover:bg-green-700" on:click={() => window.open(`https://localhost:6969/${cert.name}/cert`, '_blank')}>
          Download Cert
        </button>
        <button class="bg-yellow-600 text-white px-3 py-1 rounded hover:bg-yellow-700" on:click={() => window.open(`https://localhost:6969/${cert.name}/key`, '_blank')}>
          Download Key
        </button>
        <button class="border px-3 py-1 rounded flex items-center gap-1" on:click={() => copyCurl(cert.name)}>
          <Copy size={16} /> Copy curl
        </button>
      </div>
    </div>
  {/each}

  {#if showModal}
    <!-- Modal -->
    <div class="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center z-50">
      <div class="bg-white p-6 rounded shadow w-full max-w-md space-y-4">
        <h2 class="text-xl font-bold">Generate Certificate</h2>
        <input class="w-full border p-2 rounded" placeholder="Name" bind:value={name} />
        <input class="w-full border p-2 rounded" placeholder="Domain" bind:value={domain} />
        <input class="w-full border p-2 rounded" placeholder="Folder" bind:value={folder} />
        <label for="client">Client (mTLS) Cert?</label>
        <input name="client" class="rounded" type="checkbox" bind:checked={client} />
        <div class="flex justify-end gap-2">
          <button class="px-4 py-2 border rounded" on:click={() => (showModal = false)}>Cancel</button>
          <button class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700" on:click={generateCert}>Generate</button>
        </div>
      </div>
    </div>
  {/if}
</div>

