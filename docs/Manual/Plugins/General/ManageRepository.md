---
abstract: Manages the profile repository.
args: {build_target: 'A single target to build. (type: StringParser)

    ', builder_args: 'Optional args for the builder. (type: ArrayStringParser)

    ', executable: 'The path to the rekall binary. This is used for spawning multiple
    processes. (type: String)

    ', force_build_index: 'Forces building the index. (type: Boolean)



    * Default: False', path_to_repository: 'The path to the profile repository (type:
    String)



    * Default: .', processes: 'Number of concurrent workers. (type: IntParser)



    * Default: 12', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: ManageRepository
epydoc: rekall.plugins.tools.repository_manager.ManageRepository-class.html
layout: plugin
module: rekall.plugins.tools.repository_manager
title: manage_repo
---
