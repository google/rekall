---
abstract: Collects artifacts.
args: {artifact_files: 'A list of additional yaml files to load which contain artifact
    definitions. (type: ArrayStringParser)

    ', artifacts: 'A list of artifact names to collect. (type: ArrayStringParser)

    ', copy_files: 'Copy files into the output. (type: Bool)



    * Default: False', create_timeline: 'Also generate a timeline file. (type: Bool)



    * Default: False', definitions: 'An inline artifact definition in yaml format.
    (type: ArrayStringParser)

    ', output_path: 'Path suitable for dumping files. (type: String)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1', writer: "Writer for artifact results. (type: Choices)\n\n\n* Valid\
    \ Choices:\n    - Zip\n    - Directory\n"}
class_name: ArtifactsCollector
epydoc: rekall.plugins.response.forensic_artifacts.ArtifactsCollector-class.html
layout: plugin
module: rekall.plugins.response.forensic_artifacts
title: artifact_collector
---
