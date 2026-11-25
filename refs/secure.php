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
  $s = $db->prepare("INSERT INTO users(username,password) VALUES(?,?)"); $s->execute([$_POST['username'] ?? '', password_hash($_POST['password'] ?? '', PASSWORD_DEFAULT)]); j(201, ['ok' => true]);
}
if ($path == '/login' && $m == 'POST') {
  $u = $_POST['username'] ?? ''; $p = $_POST['password'] ?? '';
  $s = $db->prepare("SELECT * FROM users WHERE username=?"); $s->execute([$u]); $row = $s->fetch(PDO::FETCH_ASSOC);
  if ($row && password_verify($p, $row['password'])) { $_SESSION['u'] = $row['username']; j(200, ['ok' => true]); }
  j(401, ['ok' => false]);
}
if ($path == '/items' && $m == 'POST') {
  if (empty($_SESSION['u'])) j(401, ['ok' => false]);
  $s = $db->prepare("INSERT INTO items(title,body) VALUES(?,?)"); $s->execute([$_POST['title'] ?? '', $_POST['body'] ?? '']);
  j(201, ['ok' => true, 'id' => (int)$db->lastInsertId()]);
}
if ($path == '/items' && $m == 'GET') {
  $q = $_GET['q'] ?? ''; $h = fn($v) => htmlspecialchars($v, ENT_QUOTES); echo "<html><body><h1>Results for: " . $h($q) . "</h1>";
  $s = $db->prepare("SELECT * FROM items WHERE title LIKE ?"); $s->execute(['%' . $q . '%']);
  foreach ($s as $x) echo "<a href='/items/" . (int)$x['id'] . "'>" . $h($x['title']) . "</a><br>";
  exit;
}
if (preg_match('#^/items/(\d+)$#', $path, $mm) && $m == 'GET') {
  $s = $db->prepare("SELECT * FROM items WHERE id=?"); $s->execute([$mm[1]]); $x = $s->fetch(PDO::FETCH_ASSOC);
  if (!$x) { http_response_code(404); exit('not found'); }
  $h = fn($v) => htmlspecialchars($v, ENT_QUOTES); echo "<html><body><h1>" . $h($x['title']) . "</h1><p>" . $h($x['body']) . "</p>";
  $c = $db->prepare("SELECT text FROM comments WHERE item_id=?"); $c->execute([$mm[1]]);
  foreach ($c as $y) echo "<div>" . $h($y['text']) . "</div>"; exit;
}
if (preg_match('#^/items/(\d+)/comments$#', $path, $mm) && $m == 'POST') {
  if (empty($_SESSION['u'])) j(401, ['ok' => false]);
  $s = $db->prepare("INSERT INTO comments(item_id,text) VALUES(?,?)"); $s->execute([$mm[1], $_POST['text'] ?? '']); j(201, ['ok' => true]);
}
http_response_code(404); echo 'not found';
