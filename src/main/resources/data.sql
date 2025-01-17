INSERT INTO roles (nombre_rol) VALUES ("USUARIO"), ("ADMINISTRADOR")
ON DUPLICATE KEY UPDATE nombre_rol=VALUES(nombre_rol);

INSERT INTO categorias (nombre, imagen) VALUES
("PlayStation 3", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+plataformas/icons8-play-station-48.png"),
("PlayStation 4", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+plataformas/icons8-play-station-48.png"),
("PlayStation 5", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+plataformas/icons8-play-station-48.png"),
("Xbox", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+plataformas/icons8-xbox-48.png"),
("Nintendo Switch", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+plataformas/icons8-nintendo-switch-60.png")
ON DUPLICATE KEY UPDATE nombre=VALUES(nombre), imagen=VALUES(imagen);

INSERT INTO caracteristicas (nombre, imagen) VALUES
("Terror", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/terror.png"),
("Suspenso", "imgSuspenso"),
("Rol", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/rol.png"),
("Carrera", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/carrera.png"),
("Moba", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/moba.png"),
("Deportes", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/deporte.png"),
("Estrategia", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/estrategia.png"),
("Musica", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/musica.png"),
("Arcade", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/arcade.png"),
("Accion", "imgAcc"),
("Simulacion", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/simulacion.png"),
("FPS", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/arma.png"),
("ATP", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/ATP.png"),
("Contenido Sexual", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/contenido+sexual.png"),
("Contenido Violento", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/contenido+violento.png"),
("Mayor 16años", "img+16"),
("Mayor 18 años", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/18.png"),
("Dificultad baja", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/nivelBajo.png"),
("Dificultad media", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/nivelMedio.png"),
("Dificultad alta", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/nivelAlto.png"),
("Single Player", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/joystick.png"),
("MultiPlayer", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/iconos+caracteristicas/joystick.png")
ON DUPLICATE KEY UPDATE nombre=VALUES(nombre), imagen=VALUES(imagen);

INSERT INTO videojuegos (nombre, descripcion, imagenes, categoria_id) VALUES
("Persona 5: Royal", "Los eventos de Persona 5 se desarrollan en Tokio y narran los sucesos de vida de Ren Amamiya, después de ser transferido al Instituto Shujin, al ser condenado a un año de libertad condicional por un delito de agresión del que fue falsamente acusado. Durante el curso escolar, él y varios de sus compañeros despiertan los poderes de sus Personas y se convierten en los \"Ladrones Fantasma de Corazones\" (Phantom Thieves of Hearts), justicieros enmascarados que se dedican a recorrer un mundo sobrenatural llamado Metaverso, robando y cambiando los deseos corruptos en el corazón de la gente.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/P5R-1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/P5R-2.jpg", 1),
("Resident Evil 4", "En Resident Evil 4 , el agente especial Leon S. Kennedy es enviado en una misión para rescatar a la hija del presidente de los Estados Unidos que ha sido secuestrada. Al encontrar su camino hacia una aldea rural en Europa, se enfrenta a nuevas amenazas que se alejan de los tradicionales enemigos zombis pesados ​​de las entregas anteriores de la serie. León lucha contra nuevas criaturas horribles infestadas por una nueva amenaza llamada Las Plagas y se enfrenta a un grupo agresivo de enemigos, incluidos aldeanos controlados mentalmente que están vinculados a Los Iluminados, el misterioso culto que está detrás del secuestro.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/img1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/img2.jpg", 2),
("Elden Ring", "Recorre este impresionante mundo a pie o a caballo, en solitario u online con otros jugadores. Sumérgete en las verdes llanuras, en los pantanos agobiantes, en las montañas tortuosas, en unos castillos que no auguran nada bueno y en otros parajes majestuosos.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/ER1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/ER2.jpg", 2),
("The Legend of Zelda: Tears of the Kingdom", "ecuela directa de Breath of the Wild, por lo que narra la historia del reino de Hyrule luego de que la malicia de Ganon, un aura maligna que ha contaminado el mundo, se desata. Ahora será responsabilidad de Link y Zelda salvar al reino, aunque nada será tan fácil como suena.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/Zelda-1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/Zelda-2.jpg", 4),
("Baldur's Gate 3", "El título está ambientado en el año 1492 DR, 120 años después de los eventos de Baldur's Gate 2. El protagonista fue capturado e implantado con un parásito que lo convertirá en una fuerza oscura, pero logra escaparse y encontrarse con otros sobrevivientes.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/BG1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/BG2.jpg", 1),
("Super Mario Odyssey", "Reuniendo el espíritu de las plataformas clásicas, y apostando por un cambio de ambientación, Super Mario Odyssey nos invitará a encarnar una vez más al fontanero más famoso del ocio electrónico en una aventura en la que visitaremos nuevos y diversos mundos, reinos y lugares enigmáticos a bordo de nuestra aeronave.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/SMO-1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/SMO-2.jpg", 3),
("Persona 4 Golden", "Persona 4 se lleva a cabo en un pueblo ficticio de Japón conocido como Inaba, y se encuentra en unas llanuras de inundación; tiene su propio instituto escolar y distritos de venta. Homicidios inexplicables se han estado presentando en este pequeño pueblo, donde los cuerpos de las víctimas aparecen colgando de antenas de televisión; se desconoce el motivo/causa de su muerte. Al mismo tiempo, corre el rumor de que ver la tele apagada en una medianoche lluviosa revelará el alma gemela de esa persona. El juego sigue a los personajes al Mundo TV, una dimensión llena de criaturas llamadas Sombras.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/P4G-1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/P4G-2.jpg", 3),
("The Last of Us Remasterizado", "Joel, un superviviente de carácter recio, es contratado para sacar de contrabando a Ellie, una niña de 14 años, fuera de una opresiva zona de cuarentena. Lo que comienza como un pequeño trabajo pronto se convierte en un viaje brutal y desgarrador, ya que ambos deben atravesar los EE. UU.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/TLOU-1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/TLOU-2.jpg", 5),
("Grand Theft Auto V", "Cuando un joven estafador callejero, un ladrón de bancos retirado y un psicópata aterrador se ven involucrados con lo peor y más desquiciado del mundo criminal, del gobierno de los EE. UU. y de la industria del espectáculo, tendrán que llevar a cabo una serie de peligrosos golpes para sobrevivir en una ciudad implacable en la que no pueden confiar en nadie. Y mucho menos los unos en los otros.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/GTAV-1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/GTAV-2.jpg", 1),
("Portal 2", "Después de demostrar cómo tenía que ser un juego de puzles en primer persona con el primer Portal (2007), siendo una aventura tan redonda que parecía difícilmente mejorable, Valve se volvió a superar, un título más ambicioso, complejo y simpático, y con modo cooperativo, para ofrecer uno de los mejores juegos de puzles de la historia.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/Portal-1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/Portal-2.jpg", 2),
("The Elder Scrolls V: Skyrim", "La historia se centra en los esfuerzos del personaje, Dovahkiin (Sangre de dragón), para derrotar a Alduin, un dragón o «dovah» que, según la profecía, destruirá el mundo.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/Skyrim-1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/Skyrim-2.jpg", 3),
("BioShock", "BioShock 2 es un videojuego de terror y de disparos en primera persona, desarrollado por 2K Marin, y la segunda parte y secuela de BioShock.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/BS-1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/BS2.jpg", 4),
("God of War", "God of War es la vuelta de Kratos a los videojuegos tras la trilogía original. Esta nueva entrega para PlayStation 4, si bien mantendrá varios de los ingredientes indivisibles de su jugabilidad, apostará por un nuevo comienzo para el personaje y una ambientación nórdica, ofreciéndonos una perspectiva más madura y realista de la mitología de dioses y monstruos milenarios habitual en la serie de títulos. En God of War, Kratos será un guerrero más curtido y pasivo, pues tendrá que desempeñar el rol de padre en un frío y hostil escenario, al que parece haberse retirado para olvidar su pasado.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/GoW1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/GoW2.jpg", 4),
("The Witcher 3: Wild Hunt", "El jugador controlará una vez más a Geralt de Rivia, el afamado cazador de monstruos, (también conocido como el Lobo Blanco) y se enfrentará a un diversificadísimo bestiario y a unos peligros de unas dimensiones nunca vistas hasta el momento en la serie, mientras recorre los reinos del Norte. Durante su aventura, tendrá que hacer uso de un gran arsenal de armas, armaduras y todo tipo de magias para enfrentarse al que hasta ahora ha sido su mayor desafío, la cacería salvaje.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/Witcher1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/Witcher2.jpg", 5),
("Ori and the Will of the Wisps", "Ori and the Will of the Wisps es la continuación del emblemático videojuego de plataformas y aventuras Ori and the Blind Forest, desarrollado por Moon Studios. Se trata de una secuela que sigue ofreciéndonos un estilo impecable a nivel visual y jugable.", "https://gameshare-bucket.s3.sa-east-1.amazonaws.com/Ori-1.jpg,https://gameshare-bucket.s3.sa-east-1.amazonaws.com/Ori-2.jpg", 5)
ON DUPLICATE KEY UPDATE nombre=VALUES(nombre), descripcion=VALUES(descripcion), imagenes=VALUES(imagenes), categoria_id=VALUES(categoria_id);

INSERT INTO videojuego_caracteristica (caracteristica_id, videojuego_id) VALUES
(1, 2), (1, 8), (1, 7), (1, 8), (1, 12), (1, 14),
(3, 3), (3, 4), (3, 5), (3, 8), (3, 1),
(4, 9), (4, 6), (4, 10),
(7, 11), (7, 15),
(9, 10),
(10, 2), (10, 3), (10, 4), (10, 8), (10, 9), (10, 12), (10, 11), (10, 13), (10, 5), (10, 7),
(11, 1), (11, 6), (11, 7),
(12, 1),
(13, 4), (13, 6), (13, 10), (13, 15),
(15, 2), (15, 3), (15, 8), (15, 9), (15, 11), (15, 12), (15, 13), (15, 14), (15, 1), (15, 5),
(17, 9), (17, 13),
(18, 1), (18, 4), (18, 6), (18, 7),
(19, 8), (19, 9), (19, 10), (19, 11), (19, 12),
(20, 2), (20, 3), (20, 5), (20, 13), (20, 14), (20, 15),
(21, 2), (21, 3), (21, 4), (21, 5), (21, 7), (21, 9), (21, 11), (21, 12), (21, 13), (21, 14),
(22, 1), (22, 6), (22, 8), (22, 10), (21, 15)
ON DUPLICATE KEY UPDATE caracteristica_id=VALUES(caracteristica_id), videojuego_id=VALUES(videojuego_id);
