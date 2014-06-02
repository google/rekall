

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
    <div class="navbar navbar-inverse navbar-fixed-top">
      <div class="navbar-inner">
        <div class="container">
          <a class="brand" href="#">{site.name}</a>
          <div class="nav-collapse collapse">
            <ul class="nav">
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
      </div>
    </div>
"""
    return result


def default(page=None):
    return u"""
{head}
{nav}
<div class="container-fluid">
<div class="row-fluid">
  <div class="span2">
    {page.navigator}
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
  <ul class="nav nav-list">
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


@utils.memoize
def _render_categories(path):
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
        inner_html = _render_categories(page.filename)
        if inner_html:
            result += """
<li>
  <input type="checkbox" id="item-{page.url}" />
  <label for="item-{page.url}">
    {basename}
  </label>
""".format(basename=os.path.basename(page.filename), page=page)

            result += inner_html
            result += "</li>"

    # Now render the files.
    for page in sorted(files, key=lambda x: x.title):
        result += """
<li>
   <a href='{page.url}' class="tree-link">{page.title}</a>
""".format(page=page)

        # Optionally add a download button if the page has a download link.
        if page.download:
            result += """
   <a href='{page.download}'><i class="icon-download"></i></a>
""".format(page=page)
            result += """
</li>"""

    if result:
        return "<ul class='nav nav-list'>%s</ul>" % result


def categories(page=None, path=None):
    """Write navigation menu for all the plugins."""
    path = path or page.root

    result = "{page.content} <div class='css-treeview'>".format(
        page=page)

    result += _render_categories(path)
    result += "</div>"

    page.content = result

    return default(page)


def docs(page=None):
    return default(page)


def embedded(page=None):
    """Embed an iframe in the page."""

    tag = page.get("tag", "embed")

    return u"""
{head}
<div class="container-fluid">
<div class="row-fluid">
  <div class="span2">
    {nav}
  </div>
  <div class="span8" >
    {page.content}
    <{tag} src="{page.download}" width="100%" type="{page.mime}">
    </{tag}>
  </div>
  <div class="span2 sidebar">
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
def _MakeNavigatorForPlugin(plugin_path):
    return (
        "<a href='{0}/index.html'><i class='icon-hand-up'></i></a>".format(
            os.path.dirname(plugin_path)) +
        "<h3><a href='{1}/index.html'>{0}</a></h3>".format(
            os.path.basename(plugin_path),
            plugin_path) +
        "<div class='css-treeview'>" +
        _render_categories(plugin_path) +
        "</div>")


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
    page.navigator = _MakeNavigatorForPlugin(plugin_path)

    return default(page)


def downloads(page=None):
    """Create an automatic directory index for downloads."""
    result = "<div id='downloads'>"

    for root, _, files in os.walk(page.root_path, topdown=True):
        readme_files = [x for x in files if x.startswith("README")]
        readme_files = [x for x in readme_files if "html" not in x]
        if not readme_files:
            continue

        # Insert the README.md from the download directory.
        subpage = utils.ParsePage(os.path.join(root, readme_files[0]))
        result += "<h3>{0}</h3><div>".format(subpage.title)
        result += subpage.content

        result += """
<table class="table table-striped table-bordered table-hover">
<thead>
<tr><th></th><th>Name</th><th>SHA1</th><th>Size</th></tr>
</thead>
<tbody>
"""

        for name in sorted(files):
            if name in readme_files or "html" in name:
                continue

            path = os.path.join(root, name)
            sha_hash = sha.sha(open(path).read()).hexdigest()
            result += """
<tr>
  <td><a href='/{url}'><i class='icon-download'></i></a></td>
  <td><a href='/{url}'>{name}</a></td>
  <td>{sha}</td>
  <td>{size}</td>
</tr>
""".format(url=path, name=name, sha=sha_hash,
           size=os.stat(path).st_size)

        result += "</tbody></table>"
        result += "</div>"

    result += """</div>
<script>
  $('#downloads').accordion({
      collapsible: true,
      heightStyle: "fill"
   });
</script>
"""

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
