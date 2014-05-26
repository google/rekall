import os
import utils

SITE = utils.Page(
    name="Rekall Memory Forensic Framework",
    description="Rekall Memory Forensic Framework",
    )


HEAD = utils.GetInclude("_includes/head.html").format(site=SITE)
FOOT = utils.GetInclude("_includes/foot.html").format(site=SITE)
SIDEBAR = utils.GetInclude("_includes/sidebar.html")


def navigation(page=None):
    """Render navigation bar."""
    items = []
    for subpage in utils.ListPages("/"):
        if subpage.menuitem:
            items.append(
                (subpage.order, subpage.menuitem, subpage.url))

    items.sort()

    result = u"""
<nav class="nav-primary" role="navigation" >
  <ul>
"""
    for _, menuitem, url in items:
        active = ""
        if url == page.url:
            active = "active"

        result += """
        <li>
          <a class="{active}" href="{url}">
            {menuitem}
          </a>
        </li>
""".format(active=active, menuitem=menuitem, url=url)

    result += u"""
  </ul>
</nav>
"""
    return result


def default(page=None):
    return u"""
{head}
<div class="container-fluid">
<div class="row-fluid">
  <div class="span2">
    {nav}
  </div>

  <div class="span8">
    {page.content}
  </div>
  <div class="span2 sidebar">
    {sidebar}
  </div>
</div>
</div>
{foot}
""".format(head=HEAD, foot=FOOT, sidebar=SIDEBAR, page=page,
           nav=navigation(page))


def blog_nav(page=None):
    items = []
    for subpage in utils.ListPages("/posts/"):
        if subpage.layout == "blog":
            items.append(
                (subpage.date, subpage))

    items.sort()
    result = ""
    for _, post in items[:5]:
        result += """
  <ul>
    <div class="row-fluid">
      <div class="span12">
        <h2>{post.title}</h2>
        <h4>{post.date} {post.author}</h4>
        {post.abstract}
        <p>
          <a href="{post.url}">Read Post</a>
        </p>
      </div>
    </div>
  </ul>""".format(post=post)

    page.content = result

    return default(page)


def blog(page=None):
    return default(page)


def _render_categories(path):
    result = ""
    for page in utils.ListPages(path):
        if page.type == "directory":
            inner_html = _render_categories(page.filename)
            if inner_html:
                result += "<li>%s" % os.path.basename(page.filename)
                result += inner_html
                result += "</li>"
        else:
            result += """
 <li>
   <a href='{page.url}'>{page.title}</a>""".format(page=page)

        if page.download:
            result += """
     <a href='{page.download}'><i class="icon-download"></i></a>
""".format(page=page)
        result += "</li>"

    if result:
        return "<ul>%s</ul>" % result


def categories(page=None, path=None):
    """Write navigation menu for all the plugins."""
    path = path or page.root

    page.content = _render_categories(path)

    return default(page)


def docs(page=None):
    return default(page)




def embedded(page=None):
    """Embed an iframe in the page."""
    return u"""
{head}
<div class="container-fluid">
<div class="row-fluid">
  <div class="span2">
    {nav}
  </div>
  <div class="span8" >
    {page.content}
    <iframe src="{page.target}" width="100%">
    </iframe>
  </div>
  <div class="span2 sidebar">
    {sidebar}
  </div>
</div>
</div>
<script>
  $(window).resize(function(){{
    var height = $(window).height() - 100;
    $('iframe').height(height);
  }});

  $(window).resize();
</script>
{foot}
""".format(head=HEAD, foot=FOOT, sidebar=SIDEBAR, page=page,
           nav=navigation(page))


def plugin(page=None):
    page.html_abstract = utils.ConvertFromMD(page.abstract)

    page.content = u"""
<h1>{page.title}</h1>

<div class="abstract">
{page.html_abstract}
</div>

{page.content}
""".format(page=page)

    return default(page)
