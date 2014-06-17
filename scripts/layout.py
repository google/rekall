

import os
import sha
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
   <nav class="navbar navbar-inverse navbar-fixed-top"
     role="navigation">
     <div class="container-fluid">
       <div class="navbar-collapse collapse">
         <div class="navbar-header">
           <a class="navbar-brand" href="#">{site.name}</a>
         </div>
         <ul class="nav navbar-nav">
""".format(site=SITE)

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
       </div>
     </div>
   </nav>
"""
    return result


def default(page=None):
    return u"""
{head}
{nav}
<div class="container-fluid">
<div class="row">
  <div class="col-md-2">
    {page.navigator}
  </div>

  <div class="col-md-8">
    {page.content}
  </div>
  <div class="col-md-2 sidebar">
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
def _render_categories(path, width):
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

    # First render the directories in the tree.
    result = ""
    for page in sorted(directories, key=lambda x: x.title):
        inner_html = _render_categories(page.filename, width)
        if inner_html:
            result += """
<li>
  <input type="checkbox" id="item-{page.url}" />
  <label for="item-{page.url}" class="category">
    {basename}
  </label>
""".format(basename=os.path.basename(page.filename), page=page)

            result += inner_html
            result += "</li>"

    # Now render the files.
    for page in sorted(files, key=lambda x: x.title):
        abbrev = page.title
        tooltip = ""
        if len(abbrev) > width:
            abbrev = abbrev[:width] + " ..."
            tooltip = "activate_tooltip"

        result += """
<li>
   <a href='{page.url}' class="tree-link {tooltip}"  title="{page.title}">
      {abbrev}
   </a>
</li>
""".format(page=page, abbrev=abbrev, tooltip=tooltip)

    if result:
        return "<ul class='nav nav-stacked'>%s</ul>" % result


def categories(page=None, path=None):
    """Write navigation menu for all the plugins."""
    path = path or page.root

    result = "{page.content} <div class='css-treeview'>".format(
        page=page)

    width = page.width or 15
    result += _render_categories(path, width)
    result += "</div>"

    page.content = result

    return default(page)


def docs(page=None):
    return plugin(page)


def embedded_doc(page=None):
    """Embed an iframe in the page.

    Also includes the doc nav bar on the left.
    """
    plugin_path = os.path.dirname(page.url)
    width = page.width or 15
    page.navigator = _MakeNavigatorForPlugin(plugin_path, width)
    return embedded(page)


def embedded(page=None):
    """Embed an iframe in the page."""

    tag = page.get("tag", "embed")

    return u"""
{head}
{nav}
<div class="container-fluid">
<div class="row-fluid">
  <div class="col-md-2">
    {page.navigator}
  </div>
  <div class="col-md-8" >
    {page.content}
    <{tag} src="{page.download}" width="100%" type="{page.mime}">
    </{tag}>
  </div>
  <div class="col-md-2 sidebar">
    {sidebar}
  </div>
</div>
</div>
<script>
  $(window).resize(function(){{
    var height = $(window).height() - 100;
    $('{tag}').height(height);
  }});

  $(window).resize();
</script>
{foot}
""".format(head=HEAD, foot=FOOT, sidebar=SIDEBAR, page=page, tag=tag,
           nav=navigation(page))


@utils.memoize
def _MakeNavigatorForPlugin(plugin_path, width):
    args = dict(prev_url=os.path.dirname(plugin_path),
                plugin_name=os.path.basename(plugin_path),
                plugin_url=plugin_path,
                categories=_render_categories(plugin_path, width))

    args["prev"] = os.path.basename(args["prev_url"])

    return """
 <a href="{prev_url}/index.html" class="btn btn-default btn-lg btn-block">
  <span class="glyphicon glyphicon-arrow-left"></span> {prev}
 </a>

 <a href='{plugin_url}/index.html' class="btn btn-default btn-lg btn-block">
   {plugin_name}
 </a>
 <p>
 <div class='css-treeview'>
   {categories}
 </div>
""".format(**args)


def plugin(page=None):
    page.html_abstract = utils.ConvertFromMD(page.abstract)

    if page.epydoc:
        page.epydoc_link = """
<a href="/epydocs/{page.epydoc}">View Source</a>
""".format(page=page)

    # Render the args in a table.
    table = ""
    if page.args:
        table = """
<h3>Plugin Arguments</h3>
<table class='table table-striped table-bordered table-hover'>
<tbody>
"""

        for arg, arg_doc in page.args.items():
            table += "<tr><td>{arg}</td><td>{arg_doc}</td></tr>".format(
                arg=arg, arg_doc=arg_doc)
        table += """
</tbody>
</table>
"""

    page.content = u"""
<h1>{page.title}</h1>

<div class="abstract">
{page.html_abstract}
</div>

{table}

{page.epydoc_link}

{page.content}
""".format(page=page, table=table)

    plugin_path = os.path.dirname(page.url)
    width = page.width or 15
    page.navigator = _MakeNavigatorForPlugin(plugin_path, width)

    return default(page)


def _MakeDownloadPageContentTable(page, release=None):
    result = """
<table class="table table-striped table-bordered table-hover">
<thead>
<tr><th>Filename</th><th>Description</th></tr>
</thead>
<tbody>
"""
    for name, desc in page.downloads.items():
        url = "https://github.com/google/rekall/releases/download/"
        url += (page.release or release) + "/" + name
        result += """
<tr>
  <td><a href='{url}'>{name}</a></td>
  <td>{desc}</td>
</tr>
""".format(url=url, name=name, desc=desc)

    result += "</tbody></table>"

    return result


def downloads(page=None):
    """Create an automatic directory index for downloads."""
    result = page.content + "\n<div id='accordion' class='panel-group'>"
    release = page.release

    readme_files = []
    for root, _, files in os.walk(page.root_path, topdown=True):
        for x in files:
            if x in ["README.md", "README.adoc"]:
                readme_files.append(
                    utils.ParsePage(os.path.join(root, x)))

    readme_files.sort(key=lambda x: x.get("order", 10))
    for subpage in readme_files:
        subpage.content_table = _MakeDownloadPageContentTable(
            subpage, release)

        subpage.tag = sha.sha(subpage.filename).hexdigest()
        result += """
  <div class='panel panel-default'>
    <div class="panel-heading">
      <h4 class="panel-title">
        <a data-toggle="collapse" data-parent="#accordion"
         href="#{page.tag}">
         {page.title}
        </a>
      </h4>
    </div>
    <div id="{page.tag}" class="panel-collapse collapse">
      <div class="panel-body">
         {page.content}
         {page.content_table}
      </div>
    </div>
  </div>
""".format(page=subpage)

    # Close the accordion div.
    result += """</div>"""

    page.content = result

    return default(page)


def redirect(page=None):
    return """
<html><head>
<meta http-equiv="refresh" content="0; url={page.target}" />
</head>
<body>
</body>
</html>
""".format(page=page)
