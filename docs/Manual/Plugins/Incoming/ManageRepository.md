---
abstract: Manages the profile repository.
args: {build_target: 'A single target to build. (type: StringParser)

    ', builder_args: 'Optional args for the builder. (type: ArrayStringParser)

    ', executable: The path to the rekall binary. This is used for spawning multiple
    processes., force_build_index: 'Forces building the index. (type: Boolean)



    * Default: False', path_to_repository: 'The path to the profile repository


    * Default: .', processes: 'Number of concurrent workers. (type: IntParser)



    * Default: 4'}
class_name: ManageRepository
epydoc: rekall.plugins.tools.repository_manager.ManageRepository-class.html
layout: plugin
module: rekall.plugins.tools.repository_manager
title: manage_repo
---
