---
layout: full_page
menuitem: Home
order: 1
---

<div class="hero-unit">
  <div class="center">
   <img class="logo-large" src="img/Rekall.png" />
  </div>
  <div class="center">
    <h1> We can remember it for you wholesale! </h1>
  </div>
  <div class="center stage-buttons">
    <a class="btn btn-lg btn-default" href="https://github.com/google/rekall">
     <i class="fa fa-github fa-lg"></i> View on GitHub
    </a>
    <a class="btn btn-lg btn-primary" href="https://github.com/google/rekall/releases">
     <i class="fa fa-download fa-lg"></i> Download
    </a>
    <a class="btn btn-lg btn-warning" href="docs/Manual/">
     <i class="fa fa-folder-open fa-lg"></i> Manual
    </a>
  </div>
</div>


<div class="container-fluid">
 <div class="row">
   <div class="col-md-4 about-cell">
    <h1>What is Rekall?</h1>
    <p>
    Rekall is the most complete Memory Analysis framework. Rekall provides an
    end-to-end solution to incident responders and forensic analysts. From state
    of the art acquisition tools, to the most advanced open source memory
    analysis framework.
    </p>
   </div>
   <div class="col-md-4 about-cell">
    <h1>Alternatives</h1>
    <p>
    Rekall's approach to memory analysis is unqiue - Rekall leverages exact
    debugging information provided by the operating system vendors to precisely
    locate significant kernel data structures. While other tools rely on
    heuristics and signatures, Rekall aims to be the most stable and reliable
    memory analysis framework.
    </p>
    <p>
    Rekall maintains the largest
      <a href="https://github.com/google/rekall-profiles">public profile repository</a>
       for many operating system versions.
    </p>
   </div>
   <div class="col-md-4 about-cell">
    <h1>Extensibility</h1>
    <p>
    One of Rekall's main goals is to be usable as a library, as part of a larger
    system. For this end, Rekall has developed library friendly APIs, such as
    JSON bases data exporting, progress reporting and thread safe behaviour.
    </p>
    <a href="showcase.html">
     <button class="btn btn-large btn-default">
      Showcase
     </button>
    </a>
   </div>
  </div>
</div>


Rekall is now tested with Travis-CI [![Build Status](https://travis-ci.org/google/rekall.svg?branch=master)](https://travis-ci.org/google/rekall).

# News

- 2015-03-21: The upcoming Rekall workshop at [DFRWS
  Dublin](http://www.dfrws.org/2015eu/program.shtml) will feature the new
  interactive Rekall web console!