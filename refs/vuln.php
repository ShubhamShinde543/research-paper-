<?php
session_start();
$db = new PDO('sqlite:' . (getenv('DB_PATH') ?: 'app.db'));
$db->exec("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)");
$db->exec("CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, title TEXT, body TEXT)");
$db->exec("CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, item_id INTEGER, text TEXT)");
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH); $m = $_SERVER['REQUEST_METHOD'];
function j($c, $d) { http_response_code($c); header('Content-Type: application/json'); echo json_encode($d); exit; }
if ($path == '/register' && $m == 'POST') {
  $s = $db->prepare("SELECT 1 FROM users WHERE username=?"); $s->execute([$_POST['username'] ?? '']);
  if ($s->fetch()) j(409, ['ok' => false]);
  $s = $db->prepare("INSERT INTO users(username,password) VALUES(?,?)"); $s->execute([$_POST['username'] ?? '', $_POST['password'] ?? '']); j(201, ['ok' => true]);
}
if ($path == '/login' && $m == 'POST') {
  $u = $_POST['username'] ?? ''; $p = $_POST['password'] ?? '';
  $r = @$db->query("SELECT * FROM users WHERE username='$u' AND password='$p'");   // CWE-89
  $row = $r ? $r->fetch(PDO::FETCH_ASSOC) : false;
  if ($row) { $_SESSION['u'] = $row['username']; j(200, ['ok' => true]); }
  j(401, ['ok' => false]);
}
if ($path == '/items' && $m == 'POST') {
  if (empty($_SESSION['u'])) j(401, ['ok' => false]);
  $s = $db->prepare("INSERT INTO items(title,body) VALUES(?,?)"); $s->execute([$_POST['title'] ?? '', $_POST['body'] ?? '']);
  j(201, ['ok' => true, 'id' => (int)$db->lastInsertId()]);
}
if ($path == '/items' && $m == 'GET') {
  $q = $_GET['q'] ?? ''; echo "<html><body><h1>Results for: $q</h1>";   // CWE-79
  $r = @$db->query("SELECT * FROM items WHERE title LIKE '%$q%'");   // CWE-89
  if ($r) foreach ($r as $x) echo "<a href='/items/{$x['id']}'>{$x['title']}</a><br>";
  exit;
}
if (preg_match('#^/items/(\d+)$#', $path, $mm) && $m == 'GET') {
  $s = $db->prepare("SELECT * FROM items WHERE id=?"); $s->execute([$mm[1]]); $x = $s->fetch(PDO::FETCH_ASSOC);
  if (!$x) { http_response_code(404); exit('not found'); }
  echo "<html><body><h1>{$x['title']}</h1><p>{$x['body']}</p>";   // CWE-79
  $c = $db->prepare("SELECT text FROM comments WHERE item_id=?"); $c->execute([$mm[1]]);
  foreach ($c as $y) echo "<div>{$y['text']}</div>"; exit;
}
if (preg_match('#^/items/(\d+)/comments$#', $path, $mm) && $m == 'POST') {
  if (empty($_SESSION['u'])) j(401, ['ok' => false]);
  $s = $db->prepare("INSERT INTO comments(item_id,text) VALUES(?,?)"); $s->execute([$mm[1], $_POST['text'] ?? '']); j(201, ['ok' => true]);
}
http_response_code(404); echo 'not found';
