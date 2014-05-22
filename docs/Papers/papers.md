---
layout: docs
category: references
title: Papers.
---

# Papers

The following are some interesting papers published by the Rekall team and might
be useful for reference.

<ul>
{% for p in site.pages | sort: 'title' %}
  {% if p.category == "papers"%}
 <li><a href='{{p.url}}'>{{p.title}}</a></li>
  {% endif %}
{% endfor %}
</ul>
