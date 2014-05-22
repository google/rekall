---
layout: docs
category: references
title: Workshops and Presentations.
---

# Workshops and Presentations.

The following are some workshops and presentations that were delivered by the
Rekall team and might be useful for reference.

<ul>
{% for p in site.pages | sort: 'title' %}
  {% if p.category == "presentations"%}
 <li><a href='{{p.url}}'>{{p.title}}</a></li>
  {% endif %}
{% endfor %}
</ul>
