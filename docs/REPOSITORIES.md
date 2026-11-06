# Repository and submodule boundaries

The root owns the open-source core. Public modules are initialized by default; private repositories are opt-in and require their own access.

| Path | Repository | Default |
| --- | --- | --- |
| modules/sdk | Animus-OSC/argus-sdk | public checkout |
| examples/datalab-sdk | Animus-OSC/animus-datalab-sdk | public checkout |
| modules/cloud | Animus-OSC/argus-cloud | private, update=none |
| modules/enterprise | Animus-OSC/argus-enterprise | private, update=none |
| testbeds/datalab | Animus-OSC/animus-ml-datalab | private, update=none |
| research/argus-rd | Animus-OSC/argus | private, update=none |

Every gitlink pins a commit. No source is copied from private Cloud, Enterprise or DataLab into a public module. Naming a private repository does not grant access or apply the root license to it.

The source export uses only a committed R&D snapshot. The old repository, history, in-flight PRs and dirty worktrees are preserved. Public/private migration is additive and does not merge or force-push old branches.

DataLab's existing legacy enterprise submodule has an unresolved placeholder remote. The root does not invent its source or recursively initialize it. Private DataLab remains the authority for resolving that legacy extension.

DataLab SDK updates and SDK gitlink repair in DataLab are proposed separately through Draft PRs; pinning a reviewed candidate does not mean those PRs have merged.
