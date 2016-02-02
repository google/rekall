import os
import utils

SITE = utils.Page(
    name=u"Rekall Memory Forensic Framework",
    description=u"Rekall Memory Forensic Framework",
    )


HEAD = utils.GetInclude("_includes/head.html").format(site=SITE)
FOOT = utils.GetInclude("_includes/foot.html").format(site=SITE)
SIDEBAR = utils.GetInclude("_includes/sidebar.html")


def default_menuitem(subpage=None, location=None):
    u"""Generate a default menu item for a page."""
    menuitem = subpage.menuitem
    url = subpage.url
    result = u"""
        <li class="divider-vertical"></li>
        """
    active = ""
    if location == subpage.url:
        active = "active"

    result += u"""
    <li class="{active}">
     <a href="{url}">
      {menuitem}
     </a>
    </li>
    """.format(active=active, menuitem=menuitem, url=url)

    return result


def drop_down_menu(page=None, location=None):
    u"""Renders a drop down navigator to the subpage's 'root' directory."""
    menuitem = page.menuitem
    result = u"""
        <li class="divider-vertical"></li>
        """
    active = ""
    if location == page.url:
        active = "active"

    result += u"""
    <li class="{active} dropdown">
     <a class="dropdown-toggle"
      id="dropdownMenu{menuitem}"
      data-toggle="dropdown"
      aria-expanded="true">
    {menuitem}
    <span class="caret"></span>
  </a>
  <ul class="dropdown-menu" role="menu" aria-labelledby="dropdownMenu{menuitem}">
""".format(menuitem=menuitem, active=active)

    for subpage in sorted(utils.ListPages(page.root), key=lambda x: x.order):
        result += u"""
    <li role="presentation"><a role="menuitem" tabindex="-1" href="{url}">{title}</a></li>
""".format(url=subpage.url, title=subpage.title)

    result += u"""
  </ul>
 </li>
"""

    return result


def navigation(page=None):
    """Render navigation bar."""
    items = []
    for subpage in utils.ListPages("/"):
        if subpage.menuitem:
            items.append(subpage)

    items.sort(key=lambda x: x.order)

    result = u"""
  <div class="background">
   <header class="header">
    <div class="navbar navbar-fixed-top navbar-inverse">
     <div class="navbar-inner">
      <div class="container">
       <a class="navbar-brand" href="/"
          style="padding-top: 0px; padding-bottom: 0px;"
          >
          <img src="/img/Rekall-small.png" class="small_logo"></img>
       </a>
       <ul class="nav navbar-nav navbar-collapse collapse">
""".format(site=SITE)

    for subpage in items:
        renderer = globals()[
            subpage.get("menu_layout", "default_menuitem")]
        result += renderer(subpage, location=page.url)

    cwd = os.getcwd()
    if not page.filename.startswith(cwd):
        raise RuntimeError("must run script from root of tree")

    result += u"""
       <li>
        <a href="https://github.com/google/rekall/edit/gh-pages/{path}?message=Describe%20your%20change..."
           data-toggle="tooltip"
           data-placement="bottom"
           title="Improve this page"
           class="improve-docs activate_tooltip">
         <i class="glyphicon glyphicon-edit"></i>
        </a>
       </ul>

       <form class="navbar-search col-md-3 docs-search" role="search"
             action="/search.html">
       <span class="glyphicon glyphicon-search search-icon"></span>
       <input type="text" name="q" data-i-search-input="true"
         class="search-query"
         placeholder="Site Search">
       </form>
      </div>
     </div>
    </div>
   </header>
""".format(path=page.filename[len(cwd)+1:])

    return result


def default(page=None):
    cwd = os.getcwd()
    if not page.filename.startswith(cwd):
        raise RuntimeError("must run script from root of tree")

    return u"""
{head}
{nav}
<div class="container-fluid page-background container">
<div class="main">
  <div class="col-md-2">
    {page.navigator}
  </div>

  <div class="col-md-10">
    {page.content}
  </div>
</div>
</div>
{foot}
""".format(head=HEAD, foot=FOOT, page=page, nav=navigation(page))


def full_page(page=None):
    return u"""
{head}
{nav}
<div class="container-fluid page-background container">
<div class="main">
  <div class="col-md-12">
    {page.content}
  </div>
</div>
</div>
{foot}
""".format(head=HEAD, foot=FOOT, page=page,
           nav=navigation(page))


def blog_nav(page=None):
    items = []
    for subpage in utils.ListPages("/posts/"):
        if subpage.layout == "blog":
            items.append(
                (subpage.date, subpage))

    items.sort(reverse=True)
    result = ""
    for _, post in items[:15]:
        result += u"""
  <ul class="nav nav-stacked">
     <h2>{post.title}</h2>
     <h4>{post.date} {post.author}</h4>
     {post.abstract}
     <p>
     <a href="{post.url}">Read Post</a>
     </p>
  </ul>""".format(post=post)

    page.content = result

    return default(page)


def blog(page=None):
    return default(page)


@utils.memoize
def _list_subpages(path):
    directories = []
    files = []

    # Separate pages into files and directories.
    for page in utils.ListPages(path):
        if "index" in page.url:
            continue

        if page.type == "directory":
            directories.append(page)
        else:
            files.append(page)

    files.sort(key=lambda x: x.title)
    directories.sort(key=lambda x: x.title)

    return directories, files

@utils.memoize
def _render_categories(path, location=None):
    directories, files = _list_subpages(path)
    result = ""

    nav_result = ""
    # Now render the files.
    for page in sorted(files, key=lambda x: x.title):
        if location == page.url:
            nav_result += u"<li class='active'>"
        else:
            nav_result += u"<li>"

        nav_result += u"""
          <a href='{page.url}' class="category-link">
            {title}
          </a>
        </li>
        """.format(page=page, title=page.title)

    if nav_result:
        result += (u"<ul class='nav nav-pills nav-stacked'>%s</ul>" %
                   nav_result)

    nav_result = ""
    # First render the files.
    for page in sorted(directories, key=lambda x: x.title):
        if page.hidden:
            continue

        nav_result += u"""
        <li>
          <a href='{page.url}' class="category-directory-link">
            {title}
          </a>
        </li>
        """.format(page=page, title=os.path.basename(page.url))

    if nav_result:
        result += (u"<ul class='nav nav-pills nav-stacked'>%s</ul>" %
                   nav_result)

    return result


def categories(page=None, path=None):
    """Write navigation menu for all the plugins."""
    path = path or page.root

    result = u"""
    {page.content} <ul class="nav nav-sidebar">
    """.format(page=page)

    result += _render_categories(path)
    result += "</ul>"

    page.content = result

    return default(page)


def docs(page=None):
    return plugin(page)


def embedded_doc(page=None):
    """Embed an iframe in the page.

    Also includes the doc nav bar on the left.
    """
    plugin_path = os.path.dirname(page.url)
    page.navigator = _MakeNavigatorForPlugin(plugin_path, location=page.url)
    return embedded(page)


def embedded(page=None):
    """Embed an iframe in the page."""

    tag = page.get("tag", "embed")
    sidebar = ""
    presentation = page.get("presentation")
    if presentation:
        sidebar = """
<a href='{presentation}' class="btn btn-default">
  Presentation
</a>
""".format(presentation=presentation)

    return u"""
{head}
{nav}
<div class="container-fluid container">
<div class="row-fluid">
  <div class="col-md-2 navigator">
    {page.navigator}
    <a href="{page.download}" class="btn btn-default">Download</a>
  </div>
  <div class="col-md-8" >
    {page.content}
    <{tag} src="{page.download}" width="100%" type="{page.mime}" class="embedded_doc">
    </{tag}>
  </div>
  <div class="col-md-2 sidebar navigator">
    {sidebar}
  </div>
</div>
</div>
<script>
  $(window).resize(function(){{
    var height = $(window).height() - 10;
    $('{tag}').height(height);
    $('.navigator').height($(window).height());
  }});

  $(window).resize();
</script>
{foot}
""".format(head=HEAD, foot=FOOT, sidebar=sidebar, page=page, tag=tag,
           nav=navigation(page))


@utils.memoize
def _MakeNavigatorForPlugin(plugin_path, location=None):
    args = dict(prev_url=os.path.dirname(plugin_path),
                plugin_name=os.path.basename(plugin_path),
                plugin_url=plugin_path)

    args["prev"] = os.path.basename(args["prev_url"])

    result = u"""
<ul class="bs-docs-sidebar hidden-print hidden-xs hidden-sm affix rekall-side-nav">
 <a href="{prev_url}/index.html" class="btn btn-default btn-lg btn-block">
  <span class="glyphicon glyphicon-arrow-left"></span> {prev}
 </a>

 <a href='{plugin_url}/index.html' class="btn btn-default btn-lg btn-block">
   {plugin_name}
 </a>
 <p>

""".format(**args)

    directories, files = _list_subpages(plugin_path)
    nav_result = ""
    # First render the files.
    for page in sorted(directories, key=lambda x: x.title):
        if page.hidden:
            continue

        nav_result += u"""
        <li>
          <a href='{page.url}' class="category-directory-link">
            {title}
          </a>
        </li>
        """.format(page=page, title=os.path.basename(page.url))

    # Now render the directories.
    for page in sorted(files, key=lambda x: x.title):
        if location == page.url:
            nav_result += u"<li class='active'>"
        else:
            nav_result += u"<li>"

        nav_result += u"""
          <a href='#{page.title}' class="category-link">
            {title}
          </a>
        </li>
        """.format(page=page, title=page.title)

    if nav_result:
        result += u"<ul class='nav nav-pills nav-stacked'>%s</ul>" % nav_result

    result += "</ul>"

    return result


def _plugin_navbar(page):
    """Renders the bottom nav bar in the plugins view.

    Has links to next/prev plugin within the same plugin category.
    """
    plugin_path = os.path.dirname(page.url)
    _, files = _list_subpages(plugin_path)
    file_urls = [x.url for x in files]
    prev_button = ""
    next_button = ""

    try:
        idx = file_urls.index(page.url)
        if idx > 0:
            prev_button = u"""
  <ul class="nav navbar-nav navbar-left">
    <li class="active">
       <a href="{prev_url}">
         <span class="glyphicon glyphicon-arrow-left"></span>
         {prev_plugin}
       </a>
    </li>
  </ul>
""".format(prev_url=file_urls[idx-1],
           prev_plugin=files[idx-1].title)

        if idx < len(file_urls) - 1:
            next_button = u"""
  <ul class="nav navbar-nav navbar-right">
    <li class="active">
       <a href="{next_url}">
          {next_plugin}
          <span class="glyphicon glyphicon-arrow-right"></span>
       </a>
    </li>
  </ul>
""".format(next_url=file_urls[idx+1],
           next_plugin=files[idx+1].title)

        return u"""
<nav class="navbar navbar-default plugins" role="navigation">
{prev_button}
{next_button}
</nav>
""".format(prev_button=prev_button, next_button=next_button)

    except (IndexError, ValueError):
        return ""


def _render_plugin_desc(page):
    abstract = "## " + utils.trim(page.abstract or "")

    page.html_abstract = utils.ConvertFromMD(abstract)

    if page.epydoc:
        page.epydoc_link = u"""
<a class="btn btn-default epydoc_link"
   href="/epydocs/{page.epydoc}">View Source</a>
""".format(page=page)

    # Render the args in a table.
    table = ""
    if page.args:
        table = u"""
<h3>Plugin Arguments</h3>
<div class="plugins_args">
<table class='table table-condensed'>
<tbody>
"""
        for arg, arg_doc in page.args.items():
            table += "<tr><td>{arg}</td><td>{arg_doc}</td></tr>".format(
                arg=utils.ConvertFromMD(arg),
                arg_doc=utils.ConvertFromMD(arg_doc))
        table += u"""
</tbody>
</table>
</div>
"""
    page.args_table = table
    page.plugin_navbar = _plugin_navbar(page)
    page.original_content = page.content
    page.content = u"""
{page.plugin_navbar}

<h1 id="#{page.title}" class="anchor" >{page.title}</h1>
{page.epydoc_link}

<div class="abstract">
{page.html_abstract}
</div>

{page.args_table}

{page.content}

<p>
{page.plugin_navbar}
""".format(page=page)

    return page

def plugin(page=None):
    page = _render_plugin_desc(page)
    plugin_path = os.path.dirname(page.url)

    page.navigator = _MakeNavigatorForPlugin(
        plugin_path, location=page.url)

    return default(page)


def plugin_index(page):
    """Generate all the plugins in this directory in one page."""
    plugin_path = os.path.dirname(page.url)
    _, files = _list_subpages(plugin_path)
    plugins = [_render_plugin_desc(x) for x in files]

    page.plugin_navbar = _plugin_navbar(page)

    page.content = u"""
<div class="plugin_doc">
<h1 id="{page.title}" class="anchor" >{page.title}</h1>

{page.content}
""".format(page=page)
    for desc in plugins:
        page.content += """
<h1 id="{page.title}" class="anchor">{page.title}</h1>
{page.epydoc_link}

<div class="plugin_description">
<div class="abstract">
{page.html_abstract}
</div>

{page.args_table}

{page.original_content}
</div>
""".format(page=desc)

    page.navigator = _MakeNavigatorForPlugin(
        plugin_path, location=page.url)

    return default(page)




def _MakeDownloadPageContentTable(page, release=None):
    result = u"""
<table class="table table-striped table-bordered table-hover">
<thead>
<tr><th>Filename</th><th>Description</th></tr>
</thead>
<tbody>
"""
    for name, desc in page.downloads.items():
        if name.startswith("http"):
            url = name
            name = os.path.basename(name)
        else:
            url = "https://github.com/google/rekall/releases/"
            url += (page.release or release) + "/"

        result += u"""
<tr>
  <td><a href='{url}'>{name}</a></td>
  <td>{desc}</td>
</tr>
""".format(url=url, name=name, desc=desc)

    result += "</tbody></table>"

    return result


def download(page=None):
    page.content += u"""
<a href="https://github.com/google/rekall/releases">
 <button class="btn btn-large btn-success">
   Go get it now!
 </button>
</a>
"""

    return default(page)


def redirect(page=None):
    return u"""
<html><head>
<meta http-equiv="refresh" content="0; url={page.target}" />
</head>
<body>
</body>
</html>
""".format(page=page)


def images(page=None):
    u"""Shows a gallery of images from a directory."""

    files = sorted(
        [x for x in os.listdir(page.image_path) if x.endswith("jpg")])

    result = '''
<div  id="carousel-example-generic"  class="carousel slide" data-ride="carousel">
'''
    result += '<ol class="carousel-indicators">'
    for i, filename in enumerate(files):
        active = ""
        if i == 0:
            active = 'active'

        result += u"""
          <li  data-target="#carousel-example-generic"
               data-slide-to="{i}" class="{active}"></li>
""".format(i=i, active=active)

    result += "</ol>"

    result += '<div class="carousel-inner">'
    for i, filename in enumerate(files):
        active = ""
        if i == 0:
            active = 'active'

        result += u"""
       <div class="item {active}">
          <img src="/{page.image_path}/{filename}"/>
       </div>
""".format(page=page, filename=filename, active=active)
    result += '</div>'


    result += u"""
  <!-- Controls -->
  <a class="left carousel-control" href="#carousel-example-generic" role="button" data-slide="prev">
    <span class="glyphicon glyphicon-chevron-left"></span>
  </a>
  <a class="right carousel-control" href="#carousel-example-generic" role="button" data-slide="next">
    <span class="glyphicon glyphicon-chevron-right"></span>
  </a>
"""

    result += u"""
</div>
<script>
    $('.carousel').carousel({
        interval: 3000,
    })
</script>
"""
    page.content += result

    return default(page)
